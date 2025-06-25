package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

// setupACME 配置并返回一个用于ACME的tls.Config。
// MODIFIED: It now takes a context for graceful shutdown and returns a channel
// to signal startup success or failure of the challenge server.
func setupACME(ctx context.Context, cfg *TLSConfig) (*tls.Config, <-chan error, error) {
	// 创建缓存目录
	err := os.MkdirAll(cfg.CacheDir, 0700)
	if err != nil {
		return nil, nil, err
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.Email,
		Cache:      autocert.DirCache(cfg.CacheDir),
	}

	// Channel to signal startup error
	startupErrChan := make(chan error, 1)

	// 启动一个HTTP服务器以响应ACME挑战
	go func() {
		challengeServer := &http.Server{
			Addr:    ":80",
			Handler: manager.HTTPHandler(nil),
		}

		// Goroutine to listen for context cancellation and shut down the server
		go func() {
			<-ctx.Done()
			logrus.Infoln("[ACME] Shutting down HTTP challenge server...")
			// Give it a moment to finish ongoing challenges
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			challengeServer.Shutdown(shutdownCtx)
		}()

		logrus.Infoln("[ACME] Starting HTTP challenge server on :80 for domain", cfg.Domain)
		err := challengeServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			// 这个错误通常是端口被占用，对于长时间运行的服务来说，应该被记录下来
			logrus.Errorln("[ACME] HTTP challenge server failed:", err)
			startupErrChan <- err // Signal the fatal error
		}
		close(startupErrChan) // Signal that the goroutine is done
	}()

	tlsConfig := manager.TLSConfig()
	// 确保 NextProtos 包含 acme-tls/1 以支持 TLS-ALPN-01 挑战
	// autocert 会自动处理
	return tlsConfig, startupErrChan, nil
}