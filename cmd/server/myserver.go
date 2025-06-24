package main

import (
	"crypto/tls"
)

type myServer struct {
	tlsConfig   *tls.Config
	fallbackCfg FallbackConfig // MODIFIED: Store the whole fallback config struct
}

// MODIFIED: NewMyServer now accepts a FallbackConfig struct
func NewMyServer(tlsConfig *tls.Config, fallbackCfg FallbackConfig) *myServer {
	s := &myServer{
		tlsConfig:   tlsConfig,
		fallbackCfg: fallbackCfg,
	}
	return s
}