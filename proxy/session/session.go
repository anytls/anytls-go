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

// Session represents a multiplexed connection for a single client.
type Session struct {
	conn net.Conn

	streams    map[uint32]*Stream
	streamLock sync.RWMutex

	// die channel is closed when the session is terminated.
	die     chan struct{}
	dieOnce sync.Once
	dieHook func()

	// writeCh is a buffered channel for outgoing frames.
	// This eliminates lock contention on the connection writer.
	writeCh chan *buf.Buffer

	padding *atomic.TypedValue[*padding.PaddingFactory]

	peerVersion byte

	onNewStream func(stream *Stream)
}

// NewServerSession creates a new server-side session.
func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
		die:         make(chan struct{}),
		streams:     make(map[uint32]*Stream),
		writeCh:     make(chan *buf.Buffer, 128),
	}
	return s
}

// Run starts the session's read and write loops.
func (s *Session) Run() {
	go s.writeLoop()
	s.recvLoop()
}

// writeLoop is the dedicated writer goroutine for the session.
func (s *Session) writeLoop() {
	defer s.Close()
	for {
		select {
		case b, ok := <-s.writeCh:
			if !ok {
				return
			}
			_, err := s.conn.Write(b.Bytes())
			b.Release()
			if err != nil {
				logrus.Debugln("Session writeLoop error:", err)
				return
			}
		case <-s.die:
			return
		}
	}
}

// IsClosed checks if the session has been closed.
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close terminates the session and all associated streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		close(s.writeCh)
		once = true
	})

	if !once {
		return io.ErrClosedPipe
	}

	if s.dieHook != nil {
		s.dieHook()
		s.dieHook = nil
	}

	s.streamLock.Lock()
	streamsToClose := make([]*Stream, 0, len(s.streams))
	for _, stream := range s.streams {
		streamsToClose = append(streamsToClose, stream)
	}
	s.streams = make(map[uint32]*Stream)
	s.streamLock.Unlock()

	for _, stream := range streamsToClose {
		stream.Close()
	}

	return s.conn.Close()
}

// recvLoop reads incoming frames from the connection and dispatches them.
func (s *Session) recvLoop() {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		_, err := io.ReadFull(s.conn, hdr[:])
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				logrus.Debugln("Session recvLoop header error:", err)
			}
			return
		}

		sid := hdr.StreamID()
		length := hdr.Length()
		lr := io.LimitReader(s.conn, int64(length))

		switch hdr.Cmd() {
		case cmdPSH:
			if length > 0 {
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()

				if ok {
					buffer := buf.Get(int(length))
					if _, err := io.ReadFull(lr, buffer); err == nil {
						select {
						case stream.dataCh <- buffer:
						default:
							logrus.Warnf("Stream %d buffer is full. Dropping packet.", sid)
							buf.Put(buffer)
						}
					} else {
						buf.Put(buffer)
						logrus.Debugln("Session recvLoop data error:", err)
						return
					}
				} else {
					io.Copy(io.Discard, lr)
				}
			}
		case cmdSYN:
			if !receivedSettingsFromClient {
				if _, err := s.writeFrame(newFrame(cmdAlert, 0)); err != nil {
					return
				}
				return
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
			if length > 0 {
				io.Copy(io.Discard, lr)
			}
		case cmdSettings:
			if length > 0 {
				buffer := buf.Get(int(length))
				if _, err := io.ReadFull(lr, buffer); err != nil {
					buf.Put(buffer)
					return
				}

				receivedSettingsFromClient = true
				m := util.StringMapFromBytes(buffer)
				paddingF := s.padding.Load()
				if m["padding-md5"] != paddingF.Md5 {
					f := newFrame(cmdUpdatePaddingScheme, 0)
					f.data = paddingF.RawScheme
					// MODIFIED (Final Fix): Handle potential write error.
					if _, err := s.writeFrame(f); err != nil {
						buf.Put(buffer)
						return
					}
				}
				if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
					s.peerVersion = byte(v)
					f := newFrame(cmdServerSettings, 0)
					f.data = util.StringMap{"v": "2"}.ToBytes()
					// MODIFIED (Final Fix): Handle potential write error.
					if _, err := s.writeFrame(f); err != nil {
						buf.Put(buffer)
						return
					}
				}
				buf.Put(buffer)
			}
		case cmdHeartRequest:
			// MODIFIED (Final Fix): Handle potential write error.
			if _, err := s.writeFrame(newFrame(cmdHeartResponse, sid)); err != nil {
				return
			}
		case cmdSYNACK, cmdAlert, cmdUpdatePaddingScheme, cmdHeartResponse, cmdServerSettings:
			if length > 0 {
				io.Copy(io.Discard, lr)
			}
		default:
			logrus.Warnf("Unknown command received: %d. Closing session.", hdr.Cmd())
			return
		}
	}
}

func (s *Session) streamClosed(sid uint32) {
	if s.IsClosed() {
		return
	}
	s.writeFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
}

func (s *Session) writeFrame(frame frame) (int, error) {
	if s.IsClosed() {
		return 0, io.ErrClosedPipe
	}

	dataLen := len(frame.data)
	if dataLen > MaxFrameSize {
		return 0, fmt.Errorf("frame data size %d exceeds maximum %d", dataLen, MaxFrameSize)
	}

	buffer := buf.NewSize(dataLen + FrameHeaderSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	select {
	case s.writeCh <- buffer:
		return dataLen, nil
	case <-s.die:
		buffer.Release()
		return 0, io.ErrClosedPipe
	}
}