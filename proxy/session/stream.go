package session

import (
	"anytls/proxy/pipe"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// Stream implements net.Conn
type Stream struct {
	id   uint32
	sess *Session

	pipeR *pipe.PipeReader
	pipeW *pipe.PipeWriter

	// Each stream has its own data channel to prevent head-of-line blocking.
	dataCh chan []byte

	// dieOnce protects the shutdown process of the stream.
	dieOnce sync.Once
	dieErr  error

	reportOnce sync.Once
}

// newStream initiates a Stream struct and its dedicated data processing loop.
func newStream(id uint32, sess *Session) *Stream {
	s := &Stream{
		id:     id,
		sess:   sess,
		dataCh: make(chan []byte, 128), // Buffered channel for incoming data
	}
	s.pipeR, s.pipeW = pipe.Pipe()

	// Start a dedicated goroutine for this stream to push data into its pipe.
	// This decouples the session's read loop from the stream's consumer backpressure.
	go s.pushDataLoop()

	return s
}

// pushDataLoop reads from the data channel and writes to the internal pipe.
// This loop terminates when the data channel is closed.
func (s *Stream) pushDataLoop() {
	// When the loop exits, ensure the write pipe is closed to unblock any readers.
	defer s.pipeW.Close()

	for data := range s.dataCh {
		// This write can block if the application isn't reading from the stream.
		_, err := s.pipeW.Write(data)
		buf.Put(data) // Return the buffer to the pool after writing or on error.
		if err != nil {
			// The pipe was likely closed by the reader side.
			// The stream is effectively dead, so we can exit.
			return
		}
	}
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if err == io.EOF && s.dieErr != nil {
		return n, s.dieErr
	}
	return n, err
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	f := newFrame(cmdPSH, s.id)
	f.data = b
	return s.sess.writeFrame(f)
}

// Close implements net.Conn
func (s *Stream) Close() error {
	return s.CloseWithError(io.ErrClosedPipe)
}

func (s *Stream) CloseWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.dieErr = err
		// Close the data channel to signal pushDataLoop to exit.
		close(s.dataCh)
		// Close the read side of the pipe, which will unblock any waiting Read calls.
		s.pipeR.CloseWithError(err)
		once = true
	})

	if once {
		// MODIFIED (Deadlock Fix): Only notify the session if the session itself
		// is not already in the process of closing.
		if !s.sess.IsClosed() {
			s.sess.streamClosed(s.id)
		}
		return nil
	}
	return s.dieErr
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	// Per-stream write deadline is not supported in this simple model.
	return os.ErrInvalid
}

func (s *Stream) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	return s.sess.conn.LocalAddr()
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	return s.sess.conn.RemoteAddr()
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion >= 2 {
		if _, err := s.sess.writeFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}