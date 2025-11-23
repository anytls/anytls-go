package session

import (
	"anytls/proxy/padding"
	"anytls/util"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sirupsen/logrus"
)

var clientDebugPaddingScheme = os.Getenv("CLIENT_DEBUG_PADDING_SCHEME") == "1"

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	synDone     func()
	synDoneLock sync.Mutex

	// pool
	seq       uint64
	idleSince time.Time
	padding   *atomic.TypedValue[*padding.PaddingFactory]

	peerVersion byte

	// client
	isClient    bool
	sendPadding bool
	buffering   bool
	buffer      []byte
	pktCounter  atomic.Uint32
	prevLen     int // New: Track previous packet length for script engine

	// server
	onNewStream func(stream *Stream)
}

func NewClientSession(conn net.Conn, _padding *atomic.TypedValue[*padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		isClient:    true,
		sendPadding: true,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
		sendPadding: true, // Enable server-side padding
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func (s *Session) Run() {
	if !s.isClient {
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      util.ProgramVersionName,
		"padding-md5": s.padding.Load().Md5,
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.buffering = true
	s.writeControlFrame(f)

	go s.recvLoop()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.closeLocally()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

// OpenStream is used to create a new stream for CLIENT
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s)

	if sid >= 2 && s.peerVersion >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = util.NewDeadlineWatcher(time.Second*3, func() {
			s.Close()
		})
		s.synDoneLock.Unlock()
	}

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		return nil, err
	}

	s.buffering = false // proxy Write it's SocksAddr to flush the buffer

	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	select {
	case <-s.die:
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
		return stream, nil
	}
}

func (s *Session) recvLoop() error {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		// read header first
		if _, err := io.ReadFull(s.conn, hdr[:]); err == nil {
			sid := hdr.StreamID()
			switch hdr.Cmd() {
			case cmdPSH:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err == nil {
						s.streamLock.RLock()
						stream, ok := s.streams[sid]
						s.streamLock.RUnlock()
						if ok {
							stream.pipeW.Write(buffer)
						}
						buf.Put(buffer)
					} else {
						buf.Put(buffer)
						return err
					}
				}
			case cmdSYN:
				if !s.isClient && !receivedSettingsFromClient {
					f := newFrame(cmdAlert, 0)
					f.data = []byte("client did not send its settings")
					s.writeControlFrame(f)
					return nil
				}
				s.streamLock.Lock()
				if _, ok := s.streams[sid]; !ok {
					stream := newStream(sid, s)
					s.streams[sid] = stream
					go func() {
						if s.onNewStream != nil {
							s.onNewStream(stream)
						} else {
							stream.Close()
						}
					}()
				}
				s.streamLock.Unlock()
			case cmdSYNACK:
				s.synDoneLock.Lock()
				if s.synDone != nil {
					s.synDone()
					s.synDone = nil
				}
				s.synDoneLock.Unlock()
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok {
						stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
					}
					buf.Put(buffer)
				}
			case cmdFIN:
				s.streamLock.Lock()
				stream, ok := s.streams[sid]
				delete(s.streams, sid)
				s.streamLock.Unlock()
				if ok {
					stream.closeLocally()
				}
			case cmdWaste:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
			case cmdSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if !s.isClient {
						receivedSettingsFromClient = true
						m := util.StringMapFromBytes(buffer)
						paddingF := s.padding.Load()
						if m["padding-md5"] != paddingF.Md5 {
							f := newFrame(cmdUpdatePaddingScheme, 0)
							f.data = paddingF.RawScheme
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}
						if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
							s.peerVersion = byte(v)
							f := newFrame(cmdServerSettings, 0)
							f.data = util.StringMap{"v": "2"}.ToBytes()
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}
					}
					buf.Put(buffer)
				}
			case cmdAlert:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						logrus.Errorln("[Alert from server]", string(buffer))
					}
					buf.Put(buffer)
					return nil
				}
			case cmdUpdatePaddingScheme:
				if hdr.Length() > 0 {
					rawScheme := make([]byte, int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
						return err
					}
					if s.isClient && !clientDebugPaddingScheme {
						if padding.UpdatePaddingScheme(rawScheme) {
							logrus.Infof("[Update padding succeed] %x\n", md5.Sum(rawScheme))
						} else {
							logrus.Warnf("[Update padding failed] %x\n", md5.Sum(rawScheme))
						}
					}
				}
			case cmdHeartRequest:
				if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
					return err
				}
			case cmdHeartResponse:
				break
			case cmdServerSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						m := util.StringMapFromBytes(buffer)
						if v, err := strconv.Atoi(m["v"]); err == nil {
							s.peerVersion = byte(v)
						}
					}
					buf.Put(buffer)
				}
			default:
			}
		} else {
			return err
		}
	}
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(cmdPSH)
	binary.BigEndian.PutUint32(buffer.Extend(4), sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(data)
	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	s.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))

	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	s.conn.SetWriteDeadline(time.Time{})

	return dataLen, nil
}

func (s *Session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.buffering {
		s.buffer = slices.Concat(s.buffer, b)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = slices.Concat(s.buffer, b)
		s.buffer = nil
	}

	// Update previous packet length for state machine
	// Note: We use the length of the packet we are about to write as 'prev' for the NEXT iteration.
	// But the logic requires using the 'prev' value that was stored from the LAST iteration.
	// So we capture the current length at the end of the function.

	currentLen := len(b)

	// Execute Script / Legacy Actions
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			// Generate list of actions (Delay, Pad, etc.) based on current packet ID and previous length
			actions := paddingF.GenerateActions(pkt, s.prevLen)

			for _, act := range actions {
				switch act.Type {
				case padding.ActionDelay:
					// Execute Delay
					delay := getRandomDuration(act.Min, act.Max)
					if delay > 0 {
						time.Sleep(delay)
					}

				case padding.ActionPad:
					// Execute Padding (Logic similar to original)
					l := int(act.Min)
					if act.Max > act.Min {
						r, _ := rand.Int(rand.Reader, big.NewInt(act.Max-act.Min))
						l += int(r.Int64())
					} else if act.Min == int64(padding.CheckMark) {
						l = padding.CheckMark
					}

					remainPayloadLen := len(b)
					if l == padding.CheckMark {
						if remainPayloadLen == 0 {
							break // Break only the inner loop? Logic implies we stop processing this packet's rules?
							// Original logic: "if checkmark and no payload, stop padding for this Write"
						} else {
							continue
						}
					}

					if remainPayloadLen > l {
						// Payload is larger than pad size, split it
						_, err = s.conn.Write(b[:l])
						if err != nil {
							return 0, err
						}
						n += l
						b = b[l:]
					} else if remainPayloadLen > 0 {
						// Payload fits, but needs padding
						paddingLen := l - remainPayloadLen - headerOverHeadSize
						if paddingLen > 0 {
							pad := make([]byte, headerOverHeadSize+paddingLen)
							pad[0] = cmdWaste
							binary.BigEndian.PutUint32(pad[1:5], 0)
							binary.BigEndian.PutUint16(pad[5:7], uint16(paddingLen))
							b = slices.Concat(b, pad)
						}
						_, err = s.conn.Write(b)
						if err != nil {
							return 0, err
						}
						n += remainPayloadLen
						b = nil
					} else {
						// Only padding
						pad := make([]byte, headerOverHeadSize+l)
						pad[0] = cmdWaste
						binary.BigEndian.PutUint32(pad[1:5], 0)
						binary.BigEndian.PutUint16(pad[5:7], uint16(l))
						_, err = s.conn.Write(pad)
						if err != nil {
							return 0, err
						}
						b = nil
					}
				}
			}

			// Write any remaining payload
			if len(b) > 0 {
				n2, err := s.conn.Write(b)
				s.prevLen = currentLen // Update state
				return n + n2, err
			}
			s.prevLen = currentLen // Update state
			return n, nil

		} else {
			s.sendPadding = false
		}
	}

	s.prevLen = currentLen // Update state for next packet
	return s.conn.Write(b)
}

func getRandomDuration(min, max int64) time.Duration {
	if max <= min {
		return time.Duration(min) * time.Millisecond
	}
	i, _ := rand.Int(rand.Reader, big.NewInt(max-min))
	return time.Duration(i.Int64()+min) * time.Millisecond
}
