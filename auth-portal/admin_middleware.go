package main

import (
	"net/http"
	"strings"
)

func requireAdmin(next http.Handler) http.Handler {
	return requirePermission(permissionAdminAccess, next)
}

func prefersJSON(r *http.Request) bool {
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if accept == "" {
		return false
	}
	return strings.Contains(accept, "application/json") || strings.Contains(accept, "json")
}
