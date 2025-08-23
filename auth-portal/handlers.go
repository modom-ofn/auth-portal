package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	// If they still have an old cookie, we'll let /home resolve it.
	if hasValidSession(r) {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	render(w, "login.html", map[string]any{"BaseURL": appBaseURL})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": usernameFrom(r.Context()),
		"uuid":     uuidFrom(r.Context()),
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	uname := usernameFrom(r.Context())
	uid := uuidFrom(r.Context())

	authorized := false
	if uname == "" && uid == "" {
		log.Printf("home: no username/uuid in session; treating as not authorized")
	} else {
		ok, err := currentProvider.IsAuthorized(uid, uname)
		// If the DB was wiped (no row), clear the stale cookie and send to login.
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				clearSessionCookie(w)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			log.Printf("home authz check failed for %s (%s): %v", uname, uid, err)
		}
		authorized = ok
	}

	// Opportunistic upsert ONLY when authorized (keeps DB lean)
	if authorized {
		_, _ = upsertUser(User{
			Username:   uname,
			PlexUUID:   nullStringFrom(uid),
			PlexAccess: true,
		})
		render(w, "portal_authorized.html", map[string]any{"Username": uname})
		return
	}

	render(w, "portal_unauthorized.html", map[string]any{"Username": uname})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}