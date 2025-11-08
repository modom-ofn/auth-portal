package main

import (
	"log"
	"net/http"
	"strings"
)

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hasValidSession(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		username := strings.TrimSpace(usernameFrom(r.Context()))
		uuid := strings.TrimSpace(uuidFrom(r.Context()))
		if username == "" && uuid == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		isAdmin, err := userIsAdmin(uuid, username)
		if err != nil {
			log.Printf("requireAdmin: admin lookup failed for %s (%s): %v", username, uuid, err)
			http.Error(w, "admin verification failed", http.StatusInternalServerError)
			return
		}
		if !isAdmin {
			if prefersJSON(r) {
				respondJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin access required"})
				return
			}
			http.Error(w, "admin access required", http.StatusForbidden)
			return
		}

		if !adminFrom(r.Context()) {
			r = r.WithContext(withAdmin(r.Context(), true))
		}
		next.ServeHTTP(w, r)
	})
}

func prefersJSON(r *http.Request) bool {
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if accept == "" {
		return false
	}
	return strings.Contains(accept, "application/json") || strings.Contains(accept, "json")
}
