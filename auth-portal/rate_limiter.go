package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientLimiter
	limit   rate.Limit
	burst   int
	ttl     time.Duration
}

func newIPRateLimiter(limit rate.Limit, burst int, ttl time.Duration) *ipRateLimiter {
	if burst <= 0 {
		burst = 1
	}
	if limit <= 0 {
		limit = rate.Every(time.Minute)
	}

	return &ipRateLimiter{
		clients: make(map[string]*clientLimiter),
		limit:   limit,
		burst:   burst,
		ttl:     ttl,
	}
}

func (r *ipRateLimiter) allow(req *http.Request) bool {
	if r == nil {
		return true
	}

	key := clientIP(req)
	if key == "" {
		key = "unknown"
	}

	limiter := r.getLimiter(key)
	return limiter.Allow()
}

func (r *ipRateLimiter) getLimiter(key string) *rate.Limiter {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.clients[key]; ok {
		entry.lastSeen = now
		return entry.limiter
	}

	limiter := rate.NewLimiter(r.limit, r.burst)
	r.clients[key] = &clientLimiter{limiter: limiter, lastSeen: now}

	if r.ttl > 0 {
		r.cleanupLocked(now)
	}

	return limiter
}

func (r *ipRateLimiter) cleanupLocked(now time.Time) {
	for key, entry := range r.clients {
		if now.Sub(entry.lastSeen) > r.ttl {
			delete(r.clients, key)
		}
	}
}

func rateLimitMiddleware(limiter *ipRateLimiter, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter.allow(r) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Retry-After", "60")

		accept := strings.ToLower(r.Header.Get("Accept"))
		if strings.Contains(accept, "application/json") || strings.HasPrefix(r.URL.Path, "/mfa/") {
			respondJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "rate limit exceeded"})
			return
		}

		http.Error(w, "Too many requests", http.StatusTooManyRequests)
	})
}
