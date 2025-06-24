package main

import (
	"anytls/proxy/padding"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var passwordSha256 []byte

func main() {
	// 加载配置
	config, err := LoadConfig()
	if err != nil {
		if err == os.ErrNotExist {
			// 这是为了在生成默认配置后正常退出，以便用户可以编辑它
			os.Exit(0)
		}
		logrus.Fatalln("Failed to load configuration:", err)
	}

	if config.Password == "" {
		logrus.Fatalln("Password is not set in config.yaml. Please set a password.")
	}

	logLevel, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	if config.PaddingScheme != "" {
		if f, err := os.Open(config.PaddingScheme); err == nil {
			b, err := io.ReadAll(f)
			if err != nil {
				logrus.Fatalln(err)
			}
			if padding.UpdatePaddingScheme(b) {
				logrus.Infoln("Loaded padding scheme file:", config.PaddingScheme)
			} else {
				logrus.Errorln("Wrong format padding scheme file:", config.PaddingScheme)
			}
			f.Close()
		} else {
			logrus.Fatalln(err)
		}
	}

	var sum = sha256.Sum256([]byte(config.Password))
	passwordSha256 = sum[:]

	logrus.Infoln("[Server]", util.ProgramVersionName)
	logrus.Infoln("[Server] Listening TCP on", config.Listen)
	// MODIFIED: Check Fallback.Address
	if config.Fallback.Address != "" {
		logrus.Infoln("[Server] Fallback enabled, target:", config.Fallback.Address)
	}

	// 根据配置模式设置TLS
	var tlsConfig *tls.Config
	logrus.Infoln("[Server] Initializing TLS in '", config.TLS.Mode, "' mode.")

	switch config.TLS.Mode {
	case "acme":
		tlsConfig, err = setupACME(&config.TLS)
		if err != nil {
			logrus.Fatalln("Failed to setup ACME:", err)
		}
	case "file":
		cert, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
		if err != nil {
			logrus.Fatalln("Failed to load TLS key pair from file:", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		logrus.Infoln("[Server] Loaded TLS certificate from", config.TLS.CertFile, "and", config.TLS.KeyFile)
	case "self-signed":
		cert, err := util.GenerateKeyPair(time.Now, "localhost")
		if err != nil {
			logrus.Fatalln("Failed to generate self-signed certificate:", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}
		logrus.Warnln("[Server] Using a temporary self-signed certificate.")
	default:
		logrus.Fatalln("Internal error: unsupported TLS mode selected.")
	}

	// 启动监听
	listener, err := tls.Listen("tcp", config.Listen, tlsConfig)
	if err != nil {
		logrus.Fatalln("Listen server tcp:", err)
	}

	ctx := context.Background()
	// MODIFIED: Pass the whole Fallback config struct to the server instance
	server := NewMyServer(tlsConfig, config.Fallback)

	logrus.Infoln("[Server] Service started successfully.")
	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Errorln("Accept error:", err)
			continue
		}
		// The connection from tls.Listen is already a TLS connection.
		// We can pass it directly to the handler.
		go handleTcpConnection(ctx, c, server)
	}
}