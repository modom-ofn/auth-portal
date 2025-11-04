package main

import (
	"net/http"
	"strings"
)

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminFrom(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}

		if !hasValidSession(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if prefersJSON(r) {
			respondJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin access required"})
			return
		}

		http.Error(w, "admin access required", http.StatusForbidden)
	})
}

func prefersJSON(r *http.Request) bool {
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if accept == "" {
		return false
	}
	return strings.Contains(accept, "application/json") || strings.Contains(accept, "json")
}
