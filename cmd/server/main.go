package main

import (
	"anytls/proxy/padding"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var passwordSha256 []byte

func main() {
	listen := flag.String("l", "0.0.0.0:8443", "server listen port")
	password := flag.String("p", "", "password")
	paddingScheme := flag.String("padding-scheme", "", "padding-scheme")
	// ADDED: New flags for certificate and fallback
	certFile := flag.String("cert", "", "TLS certificate file (PEM format)")
	keyFile := flag.String("key", "", "TLS private key file (PEM format)")
	fallbackAddr := flag.String("fallback", "", "Fallback server address on auth failure, e.g., 127.0.0.1:80")

	flag.Parse()

	if *password == "" {
		logrus.Fatalln("please set password")
	}
	if *paddingScheme != "" {
		if f, err := os.Open(*paddingScheme); err == nil {
			b, err := io.ReadAll(f)
			if err != nil {
				logrus.Fatalln(err)
			}
			if padding.UpdatePaddingScheme(b) {
				logrus.Infoln("loaded padding scheme file:", *paddingScheme)
			} else {
				logrus.Errorln("wrong format padding scheme file:", *paddingScheme)
			}
			f.Close()
		} else {
			logrus.Fatalln(err)
		}
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	var sum = sha256.Sum256([]byte(*password))
	passwordSha256 = sum[:]

	logrus.Infoln("[Server]", util.ProgramVersionName)
	logrus.Infoln("[Server] Listening TCP", *listen)
	if *fallbackAddr != "" {
		logrus.Infoln("[Server] Fallback enabled, target:", *fallbackAddr)
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatalln("listen server tcp:", err)
	}

	// MODIFIED: Load certificate from file or generate self-signed
	var tlsCert *tls.Certificate
	if *certFile != "" && *keyFile != "" {
		logrus.Infoln("[Server] Loading TLS certificate from", *certFile, "and", *keyFile)
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			logrus.Fatalln("Failed to load TLS key pair:", err)
		}
		tlsCert = &cert
	} else {
		logrus.Warnln("[Server] No certificate provided, generating a self-signed certificate.")
		cert, err := util.GenerateKeyPair(time.Now, "")
		if err != nil {
			logrus.Fatalln("Failed to generate self-signed certificate:", err)
		}
		tlsCert = cert
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	ctx := context.Background()
	// MODIFIED: Pass fallback address to the server instance
	server := NewMyServer(tlsConfig, *fallbackAddr)

	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Fatalln("accept:", err)
		}
		go handleTcpConnection(ctx, c, server)
	}
}