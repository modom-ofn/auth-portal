package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type logLevel int

const (
	levelDEBUG logLevel = iota
	levelINFO
	levelWARN
	levelERROR
)

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Prefer lowercase env for parity with docker-compose; fall back to uppercase.
var (
	curLevel             = parseLogLevel(firstNonEmpty(os.Getenv("log_level"), os.Getenv("LOG_LEVEL")))
	trustedProxyNetworks = parseTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS"))
)

func parseLogLevel(s string) logLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return levelDEBUG
	case "WARN":
		return levelWARN
	case "ERROR":
		return levelERROR
	default:
		return levelINFO
	}
}

func lvlOK(want logLevel) bool { return curLevel <= want }

func Debugf(format string, v ...any) {
	if lvlOK(levelDEBUG) {
		log.Printf("DEBUG "+format, v...)
	}
}
func Infof(format string, v ...any) {
	if lvlOK(levelINFO) {
		log.Printf("INFO  "+format, v...)
	}
}
func Warnf(format string, v ...any) {
	if lvlOK(levelWARN) {
		log.Printf("WARN  "+format, v...)
	}
}
func Errorf(format string, v ...any) {
	if lvlOK(levelERROR) {
		log.Printf("ERROR "+format, v...)
	}
}

// Wrap the app to emit per-request logs in DEBUG.
func WithRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !lvlOK(levelDEBUG) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		dur := time.Since(start).Round(time.Millisecond)
		Debugf(`http %s %s -> %d %dB in %s ua=%q ip=%s`,
			r.Method, r.URL.RequestURI(), rec.status, rec.written, dur, r.UserAgent(), clientIP(r))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }
func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.written += n
	return n, err
}

func clientIP(r *http.Request) string {
	remoteHost, remoteIP := normalizeRemoteAddr(r.RemoteAddr)

	if len(trustedProxyNetworks) == 0 {
		if remoteIP != nil {
			return remoteIP.String()
		}
		return remoteHost
	}

	if remoteIP == nil {
		return remoteHost
	}

	if !isTrustedProxy(remoteIP) {
		return remoteIP.String()
	}

	if ip := clientIPFromForwarded(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}

	if ip := clientIPFromRealIP(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}

	return remoteIP.String()
}

func clientIPFromForwarded(header string) string {
	parts := parseForwardedFor(header)
	if len(parts) == 0 {
		return ""
	}

	for i := len(parts) - 1; i >= 0; i-- {
		if ip := parseIPCandidate(parts[i]); ip != nil {
			if !isTrustedProxy(ip) {
				return ip.String()
			}
		}
	}

	for _, part := range parts {
		if ip := parseIPCandidate(part); ip != nil {
			return ip.String()
		}
	}

	return ""
}

func clientIPFromRealIP(header string) string {
	ip := parseIPCandidate(header)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func parseForwardedFor(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	res := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

func normalizeRemoteAddr(addr string) (string, net.IP) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", nil
	}
	if ip := parseIPCandidate(addr); ip != nil {
		return ip.String(), ip
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, parseIPCandidate(addr)
	}
	if host == "" {
		return addr, nil
	}
	ip := parseIPCandidate(host)
	if ip != nil {
		return ip.String(), ip
	}
	return host, nil
}

func parseIPCandidate(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if i := strings.Index(raw, "%"); i != -1 {
		if strings.Count(raw, ":") >= 2 {
			raw = raw[:i]
		}
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return parseIPCandidate(host)
	}
	return nil
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range trustedProxyNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedProxies(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	networks := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			_, network, parseErr := net.ParseCIDR(part)
			if parseErr == nil {
				networks = append(networks, network)
				continue
			}
			log.Printf("Invalid TRUSTED_PROXY_CIDRS entry %q: %v", part, parseErr)
			continue
		}
		ip := parseIPCandidate(part)
		if ip == nil {
			log.Printf("Invalid TRUSTED_PROXY_CIDRS entry %q: not an IP or CIDR", part)
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			copyIP := append(net.IP(nil), v4...)
			networks = append(networks, &net.IPNet{IP: copyIP, Mask: net.CIDRMask(32, 32)})
			continue
		}
		copyIP := append(net.IP(nil), ip.To16()...)
		networks = append(networks, &net.IPNet{IP: copyIP, Mask: net.CIDRMask(128, 128)})
	}
	return networks
}
