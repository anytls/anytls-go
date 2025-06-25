package main

import (
	"anytls/proxy/padding"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
	if config.Fallback.Address != "" {
		logrus.Infoln("[Server] Fallback enabled, target:", config.Fallback.Address)
	}

	// 创建一个在接收到关闭信号时被取消的上下文
	// 这是优雅停机机制的核心
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop() // 释放与NotifyContext相关的资源

	// 初始化带缓存的拨号器，并传入根上下文
	// 这确保了其清理goroutine能随应用生命周期结束
	NewCachedDialer(ctx)

	// 根据配置模式设置TLS
	var tlsConfig *tls.Config
	logrus.Infoln("[Server] Initializing TLS in '", config.TLS.Mode, "' mode.")

	switch config.TLS.Mode {
	case "acme":
		var acmeErrChan <-chan error
		// 将可取消的上下文传递给setupACME，以便其自身进行优雅关闭
		tlsConfig, acmeErrChan, err = setupACME(ctx, &config.TLS)
		if err != nil {
			logrus.Fatalln("Failed to setup ACME:", err)
		}
		if startupErr := <-acmeErrChan; startupErr != nil {
			logrus.Fatalln("ACME challenge server failed to start, cannot continue:", startupErr)
		}
		logrus.Infoln("[ACME] HTTP challenge server started successfully.")
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

	// 创建一个WaitGroup来追踪活跃的连接
	var wg sync.WaitGroup
	server := NewMyServer(tlsConfig, config.Fallback)

	// 在goroutine中启动主服务循环，以便主线程可以阻塞并等待关闭信号
	go func() {
		logrus.Infoln("[Server] Service started successfully. Ready to accept connections.")
		for {
			c, err := listener.Accept()
			if err != nil {
				// 检查错误是否是由于在关闭期间关闭了监听器
				select {
				case <-ctx.Done():
					// 这是关闭期间的预期错误，直接返回
					return
				default:
					// 这是意外错误
					logrus.Errorln("Accept error:", err)
				}
				continue
			}

			// 为每个新连接增加WaitGroup计数
			wg.Add(1)
			go func() {
				// 当连接处理器返回时，减少计数器
				defer wg.Done()
				// 将可取消的上下文传递给处理器
				handleTcpConnection(ctx, c, server)
			}()
		}
	}()

	// 阻塞直到接收到关闭信号
	<-ctx.Done()

	// --- 开始优雅停机 ---
	logrus.Infoln("[Server] Shutdown signal received. Starting graceful shutdown...")

	// 停止监听器接受新连接
	// 这将导致服务循环的goroutine退出
	if err := listener.Close(); err != nil {
		logrus.Errorf("[Server] Error closing listener: %v", err)
	}

	// 等待所有活跃连接完成，并设置超时
	shutdownComplete := make(chan struct{})
	go func() {
		wg.Wait()
		close(shutdownComplete)
	}()

	select {
	case <-shutdownComplete:
		logrus.Infoln("[Server] All connections have been closed gracefully.")
	case <-time.After(15 * time.Second): // 15秒超时
		logrus.Warnln("[Server] Graceful shutdown timed out after 15 seconds. Forcing exit.")
	}

	logrus.Infoln("[Server] Shutdown complete.")
}