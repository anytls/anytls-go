package main

import (
	"crypto/tls"
)

type myServer struct {
	tlsConfig    *tls.Config
	fallbackAddr string // ADDED: Field to store the fallback address
}

// MODIFIED: NewMyServer now accepts a fallback address
func NewMyServer(tlsConfig *tls.Config, fallbackAddr string) *myServer {
	s := &myServer{
		tlsConfig:    tlsConfig,
		fallbackAddr: fallbackAddr,
	}
	return s
}