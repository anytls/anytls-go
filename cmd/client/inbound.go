package main

import (
	"context"
	"net"
	"runtime/debug"
	"strings"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sirupsen/logrus"
)

func handleTcpConnection(ctx context.Context, c net.Conn, s *myClient, socksUserPass *string) {
	if *socksUserPass != "" && strings.Contains(*socksUserPass, ",") {
		var users []auth.User
		users = append(users, auth.User{Username: strings.Split(*socksUserPass, ",")[0], Password: strings.Split(*socksUserPass, ",")[1]})
		authenticator := auth.NewAuthenticator(users)
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		defer c.Close()

		socks.HandleConnection(ctx, c, authenticator, s, M.Metadata{
			Source:      M.SocksaddrFromNet(c.RemoteAddr()),
			Destination: M.SocksaddrFromNet(c.LocalAddr()),
		})
	} else {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		defer c.Close()
		socks.HandleConnection(ctx, c, nil, s, M.Metadata{
			Source:      M.SocksaddrFromNet(c.RemoteAddr()),
			Destination: M.SocksaddrFromNet(c.LocalAddr()),
		})
	}
}

// sing socks inbound

func (c *myClient) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	proxyC, err := c.CreateProxy(ctx, metadata.Destination)
	if err != nil {
		logrus.Errorln("CreateProxy:", err)
		return err
	}
	defer proxyC.Close()

	return bufio.CopyConn(ctx, conn, proxyC)
}

func (c *myClient) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	proxyC, err := c.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		logrus.Errorln("CreateProxy:", err)
		return err
	}
	defer proxyC.Close()

	request := uot.Request{
		Destination: metadata.Destination,
	}
	uotC := uot.NewLazyConn(proxyC, request)

	return bufio.CopyPacketConn(ctx, conn, uotC)
}
