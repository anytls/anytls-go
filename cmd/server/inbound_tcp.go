package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
)

// MODIFIED: Define initial read timeout as a constant.
const initialReadTimeout = 5 * time.Second

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func pooledCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer c.Close()

	// MODIFIED: Make the initial read respect the context for faster shutdown.
	// This is done by racing the read operation with a context watcher.
	var n int
	var err error
	readDone := make(chan struct{})
	b := buf.NewPacket()
	defer b.Release()

	go func() {
		c.SetReadDeadline(time.Now().Add(initialReadTimeout))
		n, err = b.ReadOnceFrom(c)
		close(readDone)
	}()

	select {
	case <-readDone:
		// Read completed or timed out.
	case <-ctx.Done():
		// Shutdown was signaled. Force the read to unblock.
		c.SetReadDeadline(time.Now())
		<-readDone // Wait for the read goroutine to exit.
		err = ctx.Err()
	}

	c.SetReadDeadline(time.Time{}) // Clear deadline
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err, "from", c.RemoteAddr())
		if n > 0 { // If some data was read before error, try to fallback
			fallback(ctx, bufio.NewCachedConn(c, b), s.fallbackCfg)
		}
		return
	}
	cachedConn := bufio.NewCachedConn(c, b)

	// 验证密码
	by, err := b.ReadBytes(32)
	if err != nil || !bytes.Equal(by, passwordSha256) {
		b.Resize(0, n)
		fallback(ctx, cachedConn, s.fallbackCfg)
		return
	}
	// 读取并处理填充
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		fallback(ctx, cachedConn, s.fallbackCfg)
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		if _, err = b.ReadBytes(int(paddingLen)); err != nil {
			b.Resize(0, n)
			fallback(ctx, cachedConn, s.fallbackCfg)
			return
		}
	}

	logrus.Infoln("Client authenticated:", c.RemoteAddr())

	session := session.NewServerSession(cachedConn, func(stream *session.Stream) {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		defer stream.Close()

		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			logrus.Debugln("ReadAddrPort:", err)
			return
		}

		if strings.Contains(destination.String(), "udp-over-tcp.arpa") {
			proxyOutboundUoT(ctx, stream, destination)
		} else {
			proxyOutboundTCP(ctx, stream, destination)
		}
	}, &padding.DefaultPaddingFactory)
	session.Run()
	session.Close()
}

func fallback(ctx context.Context, c net.Conn, fallbackCfg FallbackConfig) {
	if fallbackCfg.Address == "" {
		logrus.Debugln("Authentication failed, no fallback configured. Closing connection from", c.RemoteAddr())
		c.Close()
		return
	}

	logrus.Debugln("Authentication failed, falling back to", fallbackCfg.Address, "for", c.RemoteAddr())

	var backendConn net.Conn
	var err error

	host, port, err := net.SplitHostPort(fallbackCfg.Address)
	if err != nil {
		logrus.Errorln("Invalid fallback address format:", fallbackCfg.Address, err)
		c.Close()
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if port == "443" {
		logrus.Debugln("Fallback target port is 443, dialing with TLS using cached dialer.")
		rawConn, dialErr := cachedDialer.DialContext(dialCtx, "tcp", fallbackCfg.Address)
		if dialErr != nil {
			err = dialErr
		} else {
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: fallbackCfg.InsecureSkipVerify,
			}
			tlsConn := tls.Client(rawConn, tlsConfig)
			handshakeErr := tlsConn.HandshakeContext(dialCtx)
			if handshakeErr != nil {
				err = handshakeErr
				rawConn.Close()
			} else {
				backendConn = tlsConn
			}
		}
	} else {
		logrus.Debugln("Fallback target port is not 443, dialing with plain TCP using cached dialer.")
		backendConn, err = cachedDialer.DialContext(dialCtx, "tcp", fallbackCfg.Address)
	}

	if err != nil {
		logrus.Errorln("Failed to dial fallback address", fallbackCfg.Address, ":", err)
		c.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer backendConn.Close()
		pooledCopy(backendConn, c)
	}()

	go func() {
		defer wg.Done()
		defer c.Close()
		pooledCopy(c, backendConn)
	}()

	wg.Wait()
	logrus.Debugln("Fallback connection finished for", c.RemoteAddr())
}