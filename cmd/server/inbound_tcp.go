package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"runtime/debug"
	"strings"

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

	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(c)
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err)
		return
	}
	c = bufio.NewCachedConn(c, b)

	by, err := b.ReadBytes(32)
	if err != nil || !bytes.Equal(by, passwordSha256) {
		b.Resize(0, n)
		fallback(ctx, c, s.fallbackAddr)
		return
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		fallback(ctx, c, s.fallbackAddr)
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			fallback(ctx, c, s.fallbackAddr)
			return
		}
	}

	session := session.NewServerSession(c, func(stream *session.Stream) {
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

func fallback(ctx context.Context, c net.Conn, addr string) {
	if addr == "" {
		logrus.Debugln("fallback: no address configured", c.RemoteAddr())
		return
	}
	logrus.Debugln("fallback to", addr, "from", c.RemoteAddr())

	fc, err := net.Dial("tcp", addr)
	if err != nil {
		logrus.Errorln("fallback dial:", err)
		return
	}
	defer fc.Close()

	if err := bufio.CopyConn(ctx, c, fc); err != nil {
		logrus.Debugln("fallback copy:", err)
	}
}
