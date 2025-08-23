package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func providerUI() (key, name string) {
	// currentProvider is set at startup; Name() returns "plex" or "emby"
	k := currentProvider.Name()
	switch k {
	case "emby":
		return "emby", "Emby"
	default:
		return "plex", "Plex"
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	key, name := providerUI()

	// If no session, just show login with provider branding.
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		render(w, "login.html", map[string]any{
			"BaseURL":      appBaseURL,
			"ProviderKey":  key,
			"ProviderName": name,
		})
		return
	}

	// Parse the JWT so we can check if the user row exists (avoid orphan redirect).
	tok, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	})
	if err != nil || !tok.Valid {
		clearSessionCookie(w)
		render(w, "login.html", map[string]any{
			"BaseURL":      appBaseURL,
			"ProviderKey":  key,
			"ProviderName": name,
		})
		return
	}

	claims, ok := tok.Claims.(*sessionClaims)
	if !ok || claims.UUID == "" {
		clearSessionCookie(w)
		render(w, "login.html", map[string]any{
			"BaseURL":      appBaseURL,
			"ProviderKey":  key,
			"ProviderName": name,
		})
		return
	}

	if _, err := getUserByUUID(claims.UUID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			clearSessionCookie(w)
			render(w, "login.html", map[string]any{
				"BaseURL":      appBaseURL,
				"ProviderKey":  key,
				"ProviderName": name,
			})
			return
		}
		log.Printf("login orphan check failed for %s: %v", claims.UUID, err)
		render(w, "login.html", map[string]any{
			"BaseURL":      appBaseURL,
			"ProviderKey":  key,
			"ProviderName": name,
		})
		return
	}

	http.Redirect(w, r, "/home", http.StatusFound)
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": usernameFrom(r.Context()),
		"uuid":     uuidFrom(r.Context()),
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	key, name := providerUI()

	uname := usernameFrom(r.Context())
	uid := uuidFrom(r.Context())

	authorized := false
	if uname == "" && uid == "" {
		log.Printf("home: no username/uuid in session; treating as not authorized")
	} else {
		ok, err := currentProvider.IsAuthorized(uid, uname)
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

	if authorized {
		_, _ = upsertUser(User{
			Username:    uname,
			MediaUUID:   nullStringFrom(uid),
			MediaAccess: true,
		})
		render(w, "portal_authorized.html", map[string]any{
			"Username":     uname,
			"ProviderName": name,
			"ProviderKey":  key,
		})
		return
	}
	render(w, "portal_unauthorized.html", map[string]any{
		"Username":     uname,
		"ProviderName": name,
		"ProviderKey":  key,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}