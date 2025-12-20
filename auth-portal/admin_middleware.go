package main

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

func requireAdmin(next http.Handler) http.Handler {
	return requirePermission(permAdminAccess)(next)
}

// requireAdminOnly restricts access to users marked admin (legacy flag) or with admin:all.
func requireAdminOnly(next http.Handler) http.Handler {
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

		user, err := lookupUserForAuthz(uuid, username)
		if err != nil {
			logPermissionDecision(username, uuid, false, []string{permAdminAll}, err)
			http.Error(w, "admin access required", http.StatusForbidden)
			return
		}
		adminFlag, err := adminFlagFromUser(user)
		if err != nil || !adminFlag {
			logPermissionDecision(username, uuid, false, []string{permAdminAll}, err)
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

// requirePermission enforces at least one of the supplied permissions,
// treating system admins and holders of admin:all as superusers.
func requirePermission(perms ...string) func(http.Handler) http.Handler {
	normalized := normalizePermissions(perms)
	return func(next http.Handler) http.Handler {
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

			allowed, adminLike, err := userHasAnyPermission(uuid, username, normalized)
			if err != nil {
				logPermissionDecision(username, uuid, false, normalized, err)
				status := http.StatusInternalServerError
				if errors.Is(err, sql.ErrNoRows) {
					status = http.StatusForbidden
				}
				http.Error(w, "authorization failed", status)
				return
			}
			if !allowed {
				logPermissionDecision(username, uuid, false, normalized, nil)
				if prefersJSON(r) {
					respondJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "insufficient permissions"})
					return
				}
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}

			if adminLike && !adminFrom(r.Context()) {
				r = r.WithContext(withAdmin(r.Context(), true))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func prefersJSON(r *http.Request) bool {
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if accept == "" {
		return false
	}
	return strings.Contains(accept, "application/json") || strings.Contains(accept, "json")
}
