package session

import (
	"anytls/proxy/padding"
	"anytls/util"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sirupsen/logrus"
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	padding *atomic.TypedValue[*padding.PaddingFactory]

	peerVersion byte

	onNewStream func(stream *Stream)
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	return s
}

func (s *Session) Run() {
	s.recvLoop()
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
			stream.Close()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
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
				if !receivedSettingsFromClient {
					f := newFrame(cmdAlert, 0)
					f.data = []byte("client did not send its settings")
					s.writeFrame(f)
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
			case cmdFIN:
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					stream.Close()
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

					receivedSettingsFromClient = true
					m := util.StringMapFromBytes(buffer)
					paddingF := s.padding.Load()
					if m["padding-md5"] != paddingF.Md5 {
						f := newFrame(cmdUpdatePaddingScheme, 0)
						f.data = paddingF.RawScheme
						_, err = s.writeFrame(f)
						if err != nil {
							buf.Put(buffer)
							return err
						}
					}
					// check client's version
					if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
						s.peerVersion = byte(v)
						// send cmdServerSettings
						f := newFrame(cmdServerSettings, 0)
						f.data = util.StringMap{
							"v": "2",
						}.ToBytes()
						_, err = s.writeFrame(f)
						if err != nil {
							buf.Put(buffer)
							return err
						}
					}
					buf.Put(buffer)
				}
			case cmdHeartRequest:
				if _, err := s.writeFrame(newFrame(cmdHeartResponse, sid)); err != nil {
					return err
				}
			// Commands only client should receive, but we ignore them just in case.
			case cmdSYNACK, cmdAlert, cmdUpdatePaddingScheme, cmdHeartResponse, cmdServerSettings:
				if hdr.Length() > 0 {
					// We must consume the data to keep the stream synchronized
					if _, err := io.CopyN(io.Discard, s.conn, int64(hdr.Length())); err != nil {
						return err
					}
				}
			default:
				// Unknown command, close connection to prevent desync
				return fmt.Errorf("unknown command: %d", hdr.Cmd())
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
	_, err := s.writeFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)
	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}

func (s *Session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	// Server does not use client-side buffering/padding logic, just writes directly.
	// The protocol doc does not specify padding for server-to-client traffic,
	// but if it were needed, the logic would be here. For now, we keep it simple.
	// If padding for downstream is desired, one would need a similar pktCounter and logic as the client-side had.
	// This simplified implementation assumes padding is a client-to-server concern.
	if len(b) > 0 {
		return s.conn.Write(b)
	}
	return 0, nil
}