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
		// A buffered channel to decouple stream writers from the single connection writer,
		// preventing lock contention and improving concurrent write performance.
		writeCh: make(chan *buf.Buffer, 128),
	}
	return s
}

// Run starts the session's read and write loops.
// This function blocks until the session is closed.
func (s *Session) Run() {
	// Start a dedicated goroutine for writing to the connection.
	// This is the core of the write performance optimization.
	go s.writeLoop()

	// The recvLoop will block until an error occurs or the connection is closed.
	s.recvLoop()
}

// writeLoop is the dedicated writer goroutine for the session.
// It reads from the writeCh and writes to the underlying connection,
// ensuring all writes are serialized without locks.
func (s *Session) writeLoop() {
	// If the writeLoop exits for any reason, the entire session is considered dead.
	defer s.Close()

	for {
		select {
		case b := <-s.writeCh:
			// Write the buffer's content to the connection.
			_, err := s.conn.Write(b.Bytes())
			// CORRECTED: Use the Release() method for *buf.Buffer objects.
			b.Release()
			if err != nil {
				// An error on write usually means the connection is broken.
				// The defer s.Close() will handle the cleanup.
				logrus.Debugln("Session writeLoop error:", err)
				return
			}
		case <-s.die:
			// The session is closing, so exit the write loop.
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
		// Closing the writeCh signals the writeLoop to terminate.
		close(s.writeCh)
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
	}

	return io.ErrClosedPipe
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
		// Read the frame header.
		_, err := io.ReadFull(s.conn, hdr[:])
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				logrus.Debugln("Session recvLoop header error:", err)
			}
			return
		}

		sid := hdr.StreamID()
		length := hdr.Length()

		switch hdr.Cmd() {
		case cmdPSH:
			if length > 0 {
				// Get a []byte from the pool. This is correct.
				buffer := buf.Get(int(length))
				if _, err := io.ReadFull(s.conn, buffer); err == nil {
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok {
						// Write data to the stream's internal pipe.
						// The pipe implementation handles the data synchronously, so it's safe
						// to return the buffer to the pool immediately after.
						stream.pipeW.Write(buffer)
					}
					// Return the []byte to the pool. This is correct.
					buf.Put(buffer)
				} else {
					buf.Put(buffer)
					logrus.Debugln("Session recvLoop data error:", err)
					return
				}
			}
		case cmdSYN:
			if !receivedSettingsFromClient {
				f := newFrame(cmdAlert, 0)
				f.data = []byte("client did not send its settings")
				s.writeFrame(f)
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
				// Discard waste data efficiently.
				if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
					logrus.Debugln("Session recvLoop waste error:", err)
					return
				}
			}
		case cmdSettings:
			if length > 0 {
				buffer := buf.Get(int(length))
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					buf.Put(buffer)
					logrus.Debugln("Session recvLoop settings error:", err)
					return
				}

				receivedSettingsFromClient = true
				m := util.StringMapFromBytes(buffer)
				paddingF := s.padding.Load()
				if m["padding-md5"] != paddingF.Md5 {
					f := newFrame(cmdUpdatePaddingScheme, 0)
					f.data = paddingF.RawScheme
					if _, err = s.writeFrame(f); err != nil {
						buf.Put(buffer)
						return
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
					if _, err = s.writeFrame(f); err != nil {
						buf.Put(buffer)
						return
					}
				}
				buf.Put(buffer)
			}
		case cmdHeartRequest:
			if _, err := s.writeFrame(newFrame(cmdHeartResponse, sid)); err != nil {
				return
			}
		// Commands only client should receive, but we ignore them just in case.
		case cmdSYNACK, cmdAlert, cmdUpdatePaddingScheme, cmdHeartResponse, cmdServerSettings:
			if length > 0 {
				// We must consume the data to keep the stream synchronized.
				if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
					logrus.Debugln("Session recvLoop discard error:", err)
					return
				}
			}
		default:
			// Unknown command, close connection to prevent desync.
			logrus.Warnf("Unknown command received: %d. Closing session.", hdr.Cmd())
			return
		}
	}
}

// streamClosed is called by a Stream when it's closed. It queues a FIN frame.
func (s *Session) streamClosed(sid uint32) {
	if s.IsClosed() {
		return
	}
	s.writeFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
}

// writeFrame constructs a frame and sends it to the write channel.
// It does not write to the connection directly.
func (s *Session) writeFrame(frame frame) (int, error) {
	if s.IsClosed() {
		return 0, io.ErrClosedPipe
	}

	dataLen := len(frame.data)
	if dataLen > MaxFrameSize {
		return 0, fmt.Errorf("frame data size %d exceeds maximum %d", dataLen, MaxFrameSize)
	}

	// CORRECTED: Use buf.NewSize() to get a *buf.Buffer object from the pool.
	buffer := buf.NewSize(dataLen + FrameHeaderSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	// Send the buffer to the writer goroutine. This is a non-blocking operation
	// as long as the channel buffer is not full.
	select {
	case s.writeCh <- buffer:
		return dataLen, nil
	case <-s.die:
		// Session is closed while we were trying to send.
		// Release the buffer and return an error.
		buffer.Release()
		return 0, io.ErrClosedPipe
	}
}