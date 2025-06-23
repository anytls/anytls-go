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

func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()

	c = tls.Server(c, s.tlsConfig)
	defer c.Close()

	// Perform TLS handshake explicitly to handle handshake errors
	if tlsConn, ok := c.(*tls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			logrus.Debugln("TLS handshake error:", err, "from", c.RemoteAddr())
			return
		}
	}

	b := buf.NewPacket()
	defer b.Release()

	// Set a read deadline for the initial authentication packet
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := b.ReadOnceFrom(c)
	c.SetReadDeadline(time.Time{}) // Clear the deadline
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err, "from", c.RemoteAddr())
		fallback(ctx, c, s.fallbackAddr)
		return
	}
	cachedConn := bufio.NewCachedConn(c, b)

	by, err := b.ReadBytes(32)
	if err != nil || !bytes.Equal(by, passwordSha256) {
		b.Resize(0, n)
		fallback(ctx, cachedConn, s.fallbackAddr)
		return
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		fallback(ctx, cachedConn, s.fallbackAddr)
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		if _, err = b.ReadBytes(int(paddingLen)); err != nil {
			b.Resize(0, n)
			fallback(ctx, cachedConn, s.fallbackAddr)
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

// MODIFIED: The fallback function now supports dialing TLS for HTTPS backends.
func fallback(ctx context.Context, c net.Conn, fallbackAddr string) {
	if fallbackAddr == "" {
		logrus.Debugln("Authentication failed, no fallback configured. Closing connection from", c.RemoteAddr())
		c.Close()
		return
	}

	logrus.Debugln("Authentication failed, falling back to", fallbackAddr, "for", c.RemoteAddr())

	// Dial the backend. We will decide whether to use TLS based on the port.
	var backendConn net.Conn
	var err error

	host, port, err := net.SplitHostPort(fallbackAddr)
	if err != nil {
		logrus.Errorln("Invalid fallback address format:", fallbackAddr, err)
		c.Close()
		return
	}

	// Heuristic: if port is 443, assume HTTPS and dial with TLS.
	// Otherwise, dial plain TCP.
	if port == "443" {
		logrus.Debugln("Fallback target port is 443, dialing with TLS.")
		// For TLS dialing, we need a tls.Config.
		// We can use a default one, but it's better to specify the ServerName for SNI.
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // Set to true if the backend uses a self-signed cert. For public sites, you might want this as false.
		}
		backendConn, err = tls.Dial("tcp", fallbackAddr, tlsConfig)
	} else {
		logrus.Debugln("Fallback target port is not 443, dialing with plain TCP.")
		backendConn, err = net.Dial("tcp", fallbackAddr)
	}

	if err != nil {
		logrus.Errorln("Failed to dial fallback address", fallbackAddr, ":", err)
		c.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer backendConn.Close()
		io.Copy(backendConn, c)
	}()

	go func() {
		defer wg.Done()
		defer c.Close()
		io.Copy(c, backendConn)
	}()

	wg.Wait()
	logrus.Debugln("Fallback connection finished for", c.RemoteAddr())
}