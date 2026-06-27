package main

import (
	"crypto/tls"
)

type myServer struct {
	tlsConfig    *tls.Config
	fallbackAddr string
}

func NewMyServer(tlsConfig *tls.Config, fallbackAddr string) *myServer {
	s := &myServer{
		tlsConfig:    tlsConfig,
		fallbackAddr: fallbackAddr,
	}
	return s
}
