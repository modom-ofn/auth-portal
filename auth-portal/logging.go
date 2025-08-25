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
var curLevel = parseLogLevel(firstNonEmpty(os.Getenv("log_level"), os.Getenv("LOG_LEVEL")))

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

func Debugf(format string, v ...any) { if lvlOK(levelDEBUG) { log.Printf("DEBUG "+format, v...) } }
func Infof(format string, v ...any)  { if lvlOK(levelINFO)  { log.Printf("INFO  "+format, v...) } }
func Warnf(format string, v ...any)  { if lvlOK(levelWARN)  { log.Printf("WARN  "+format, v...) } }
func Errorf(format string, v ...any) { if lvlOK(levelERROR) { log.Printf("ERROR "+format, v...) } }

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
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		p := strings.Split(xff, ",")
		return strings.TrimSpace(p[0])
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}