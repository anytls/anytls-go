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

// handleTcpConnection 处理一个已经建立的TLS连接。
func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer c.Close()

	b := buf.NewPacket()
	defer b.Release()

	// 为初始认证包设置读取超时
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := b.ReadOnceFrom(c)
	c.SetReadDeadline(time.Time{}) // 清除超时
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err, "from", c.RemoteAddr())
		// MODIFIED: Pass the fallback config struct
		fallback(ctx, c, s.fallbackCfg)
		return
	}
	cachedConn := bufio.NewCachedConn(c, b)

	// 验证密码
	by, err := b.ReadBytes(32)
	if err != nil || !bytes.Equal(by, passwordSha256) {
		b.Resize(0, n)
		// MODIFIED: Pass the fallback config struct
		fallback(ctx, cachedConn, s.fallbackCfg)
		return
	}
	// 读取并处理填充
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		// MODIFIED: Pass the fallback config struct
		fallback(ctx, cachedConn, s.fallbackCfg)
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		if _, err = b.ReadBytes(int(paddingLen)); err != nil {
			b.Resize(0, n)
			// MODIFIED: Pass the fallback config struct
			fallback(ctx, cachedConn, s.fallbackCfg)
			return
		}
	}

	logrus.Infoln("Client authenticated:", c.RemoteAddr())

	// 认证成功，创建会话
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

// MODIFIED: fallback now accepts a FallbackConfig struct.
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

	if port == "443" {
		logrus.Debugln("Fallback target port is 443, dialing with TLS.")
		tlsConfig := &tls.Config{
			ServerName:         host,
			// MODIFIED: Use the value from the config file
			InsecureSkipVerify: fallbackCfg.InsecureSkipVerify,
		}
		backendConn, err = tls.Dial("tcp", fallbackCfg.Address, tlsConfig)
	} else {
		logrus.Debugln("Fallback target port is not 443, dialing with plain TCP.")
		backendConn, err = net.Dial("tcp", fallbackCfg.Address)
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
		defer c.Close()
		io.Copy(c, backendConn)
	}()

	go func() {
		defer wg.Done()
		defer backendConn.Close()
		io.Copy(backendConn, c)
	}()

	wg.Wait()
	logrus.Debugln("Fallback connection finished for", c.RemoteAddr())
}