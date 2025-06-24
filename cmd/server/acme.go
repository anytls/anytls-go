package main

import (
	"crypto/tls"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

// setupACME 配置并返回一个用于ACME的tls.Config
func setupACME(cfg *TLSConfig) (*tls.Config, error) {
	// 创建缓存目录
	err := os.MkdirAll(cfg.CacheDir, 0700)
	if err != nil {
		return nil, err
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.Email,
		Cache:      autocert.DirCache(cfg.CacheDir),
	}

	// 启动一个HTTP服务器以响应ACME挑战
	// 这是一个非阻塞调用，会在后台运行
	go func() {
		logrus.Infoln("[ACME] Starting HTTP challenge server on :80 for domain", cfg.Domain)
		err := http.ListenAndServe(":80", manager.HTTPHandler(nil))
		if err != nil {
			// 这个错误通常是端口被占用，对于长时间运行的服务来说，应该被记录下来
			logrus.Errorln("[ACME] HTTP challenge server failed:", err)
		}
	}()

	tlsConfig := manager.TLSConfig()
	// 确保 NextProtos 包含 acme-tls/1 以支持 TLS-ALPN-01 挑战
	// autocert 会自动处理
	return tlsConfig, nil
}