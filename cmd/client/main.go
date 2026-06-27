package main

import (
	"anytls/proxy"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var passwordSha256 []byte

func main() {
	listen := flag.String("l", "127.0.0.1:1080", "socks5 listen port")
	serverAddr := flag.String("s", "", "Server address or anytls:// link")
	sni := flag.String("sni", "", "Server Name Indication")
	password := flag.String("p", "", "Password")
	minIdleSession := flag.Int("m", 5, "Reserved min idle session")
	disableReuse := flag.Bool("dr", false, "Disable client session reuse")
	flag.Parse()

	if serverURL, err := url.Parse(*serverAddr); err == nil {
		if serverURL.Scheme == "anytls" {
			*serverAddr = serverURL.Host
			if serverURL.User != nil {
				*password = serverURL.User.String()
			}
			query := serverURL.Query()
			*sni = query.Get("sni")
		}
	}

	if *serverAddr == "" {
		logrus.Fatalln("please set -s server adreess")
	}

	if *password == "" {
		logrus.Fatalln("please set -p password")
	}

	if _, _, err := net.SplitHostPort(*serverAddr); err != nil {
		logrus.Fatalln("error server address:", *serverAddr, err)
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	var sum = sha256.Sum256([]byte(*password))
	passwordSha256 = sum[:]

	logrus.Infoln("[Client]", util.ProgramVersionName)
	logrus.Infoln("[Client] socks5/http", *listen, "=>", *serverAddr)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatalln("listen socks5 tcp:", err)
	}

	// You can only use `InsecureSkipVerify` by default in the sample client; it is not recommended for use in production code.
	tlsConfig := &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true,
	}
	if tlsConfig.ServerName == "" {
		// disable the SNI
		tlsConfig.ServerName = "127.0.0.1"
	}

	path := strings.TrimSpace(os.Getenv("TLS_KEY_LOG"))
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err == nil {
			tlsConfig.KeyLogWriter = f
		}
	}

	ctx := context.Background()
	client := NewMyClient(ctx, func(ctx context.Context) (net.Conn, error) {
		conn, err := proxy.SystemDialer.DialContext(ctx, "tcp", *serverAddr)
		if err != nil {
			return nil, err
		}
		conn = tls.Client(conn, tlsConfig)
		return conn, nil
	}, *minIdleSession, *disableReuse)

	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Fatalln("accept:", err)
		}
		go handleTcpConnection(ctx, c, client)
	}
}
