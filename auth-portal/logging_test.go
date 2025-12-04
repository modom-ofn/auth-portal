package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func withTrustedProxies(t *testing.T, cidrs string) func() {
	t.Helper()
	prev := trustedProxyNetworks
	trustedProxyNetworks = parseTrustedProxies(cidrs)
	return func() { trustedProxyNetworks = prev }
}

func TestClientIPNoTrustedProxyIgnoresForwardedFor(t *testing.T) {
	cleanup := withTrustedProxies(t, "")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, testExampleURL, nil)
	req.RemoteAddr = "198.51.100.1:12345"
	req.Header.Set(testForwardHeader, "203.0.113.10")

	if got := clientIP(req); got != "198.51.100.1" {
		t.Fatalf("expected remote IP, got %q", got)
	}
}

func TestClientIPTrustedProxyUsesForwardChain(t *testing.T) {
	cleanup := withTrustedProxies(t, testProxyCIDR)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, testExampleURL, nil)
	req.RemoteAddr = "198.51.100.2:5000"
	req.Header.Set(testForwardHeader, "203.0.113.10, 198.51.100.3")

	if got := clientIP(req); got != "203.0.113.10" {
		t.Fatalf("expected client IP from forwarded chain, got %q", got)
	}
}

func TestClientIPUntrustedRemoteIgnoresSpoofedForwarded(t *testing.T) {
	cleanup := withTrustedProxies(t, testProxyCIDR)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, testExampleURL, nil)
	req.RemoteAddr = "203.0.113.1:4444"
	req.Header.Set(testForwardHeader, "198.51.100.20")

	if got := clientIP(req); got != "203.0.113.1" {
		t.Fatalf("expected remote IP when proxy untrusted, got %q", got)
	}
}

func TestClientIPTrustedProxyUsesRealIP(t *testing.T) {
	cleanup := withTrustedProxies(t, testProxyCIDR)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, testExampleURL, nil)
	req.RemoteAddr = "198.51.100.2:6000"
	req.Header.Set("X-Real-IP", "203.0.113.42")

	if got := clientIP(req); got != "203.0.113.42" {
		t.Fatalf("expected X-Real-IP when proxy trusted, got %q", got)
	}
}

func TestClientIPUntrustedRemoteIgnoresRealIP(t *testing.T) {
	cleanup := withTrustedProxies(t, testProxyCIDR)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, testExampleURL, nil)
	req.RemoteAddr = "203.0.113.1:6000"
	req.Header.Set("X-Real-IP", "198.51.100.20")

	if got := clientIP(req); got != "203.0.113.1" {
		t.Fatalf("expected remote IP when proxy untrusted, got %q", got)
	}
}

const (
	testExampleURL    = "http://example.com"
	testForwardHeader = "X-Forwarded-For"
	testProxyCIDR     = "198.51.100.0/24"
)
