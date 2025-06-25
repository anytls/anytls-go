package main

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// resolverCacheEntry holds the cached IP addresses and their expiration time.
type resolverCacheEntry struct {
	ips        []net.IPAddr
	expiration time.Time
}

// DNSResolver is a custom net.Resolver that caches DNS lookups.
type DNSResolver struct {
	cache      map[string]*resolverCacheEntry
	mu         sync.RWMutex
	ttl        time.Duration
	underlying *net.Resolver
}

// NewDNSResolver creates a new DNS resolver with an in-memory cache.
// MODIFIED: It now accepts a context to allow for graceful shutdown of its cleanup goroutine.
func NewDNSResolver(ctx context.Context, ttl time.Duration) *DNSResolver {
	resolver := &DNSResolver{
		cache: make(map[string]*resolverCacheEntry),
		ttl:   ttl,
		underlying: &net.Resolver{
			PreferGo: true,
		},
	}
	// Start a background goroutine to periodically clean up expired entries.
	// This goroutine will now stop when the provided context is canceled.
	go resolver.cleanupLoop(ctx, time.Minute)
	return resolver
}

// LookupIPAddr performs a DNS lookup, using the cache if possible.
func (r *DNSResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	// Check if the host is an IP address already.
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	r.mu.RLock()
	entry, found := r.cache[host]
	r.mu.RUnlock()

	if found && time.Now().Before(entry.expiration) {
		logrus.Tracef("[DNS Cache] HIT for %s", host)
		return entry.ips, nil
	}

	logrus.Tracef("[DNS Cache] MISS for %s, performing lookup", host)
	// Perform the actual lookup.
	ips, err := r.underlying.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	// Store the new entry in the cache.
	r.mu.Lock()
	r.cache[host] = &resolverCacheEntry{
		ips:        ips,
		expiration: time.Now().Add(r.ttl),
	}
	r.mu.Unlock()

	return ips, nil
}

// cleanupLoop periodically iterates through the cache and removes expired entries.
// MODIFIED: It now respects the context's done channel for graceful shutdown.
func (r *DNSResolver) cleanupLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			now := time.Now()
			for host, entry := range r.cache {
				if now.After(entry.expiration) {
					delete(r.cache, host)
				}
			}
			r.mu.Unlock()
		case <-ctx.Done():
			logrus.Debugln("[DNS Cache] Cleanup loop shutting down.")
			return
		}
	}
}

// CustomDialer is a net.Dialer that uses our custom DNS resolver.
type CustomDialer struct {
	dialer   *net.Dialer
	resolver *DNSResolver
}

// NewCustomDialer creates a new dialer with DNS caching capabilities.
// MODIFIED: It now accepts a context to pass to the DNSResolver.
func NewCustomDialer(ctx context.Context, timeout time.Duration, dnsTTL time.Duration) *CustomDialer {
	resolver := NewDNSResolver(ctx, dnsTTL)
	return &CustomDialer{
		dialer: &net.Dialer{
			Timeout: timeout,
			// The resolver is used in our custom DialContext.
		},
		resolver: resolver,
	}
}

// DialContext implements the dialer interface, transparently handling DNS resolution.
func (d *CustomDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	// Try to dial each resolved IP address until one succeeds.
	var firstErr error
	for _, ip := range ips {
		conn, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	return nil, firstErr
}