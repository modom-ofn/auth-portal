package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// providerUI returns the provider key used by code ("plex"/"emby")
// and the display name shown in templates (exactly as MEDIA_SERVER is typed).
func providerUI() (key, display string) {
	// Prefer exact casing from env for display
	raw := strings.TrimSpace(os.Getenv("MEDIA_SERVER"))
	if raw != "" {
		l := strings.ToLower(raw)
		switch l {
		case "plex":
			return "plex", raw // display keeps user-provided casing
		case "emby":
			return "emby", raw
		default:
			// Unknown value: keep raw for display, fall back to currentProvider for key
			k := currentProvider.Name()
			if k == "" {
				k = l
			}
			return k, raw
		}
	}

	// Fallback when env is unset: map from current provider
	switch currentProvider.Name() {
	case "emby":
		return "emby", "Emby"
	default:
		return "plex", "Plex"
	}
}

// live getters (read env each request)
func getExtraLink() (urlStr, text string) {
	return strings.TrimSpace(os.Getenv("LOGIN_EXTRA_LINK_URL")),
		strings.TrimSpace(os.Getenv("LOGIN_EXTRA_LINK_TEXT"))
}

func getRequestAccess(providerDisplay string) (email, subj, subjQP string) {
	email = strings.TrimSpace(os.Getenv("UNAUTH_REQUEST_EMAIL"))
	if email == "" {
		email = "admin@example.com"
	}
	subj = strings.TrimSpace(os.Getenv("UNAUTH_REQUEST_SUBJECT"))
	if subj == "" {
		subj = providerDisplay + " Access Request"
	}
	subjQP = url.QueryEscape(subj)
	return
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	key, name := providerUI()
	extraURL, extraText := getExtraLink()

	// If no session, show login page right away.
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		render(w, "login.html", map[string]any{
			"BaseURL":       appBaseURL,
			"ProviderKey":   key,
			"ProviderName":  name, // exact casing
			"ExtraLinkURL":  extraURL,
			"ExtraLinkText": extraText,
		})
		return
	}

	// Parse JWT to avoid redirecting with an orphaned cookie.
	tok, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	})
	if err != nil || !tok.Valid {
		clearSessionCookie(w)
		render(w, "login.html", map[string]any{
			"BaseURL":       appBaseURL,
			"ProviderKey":   key,
			"ProviderName":  name,
			"ExtraLinkURL":  extraURL,
			"ExtraLinkText": extraText,
		})
		return
	}

	claims, ok := tok.Claims.(*sessionClaims)
	if !ok || claims.UUID == "" {
		clearSessionCookie(w)
		render(w, "login.html", map[string]any{
			"BaseURL":       appBaseURL,
			"ProviderKey":   key,
			"ProviderName":  name,
			"ExtraLinkURL":  extraURL,
			"ExtraLinkText": extraText,
		})
		return
	}

	if _, err := getUserByUUID(claims.UUID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			clearSessionCookie(w)
			render(w, "login.html", map[string]any{
				"BaseURL":       appBaseURL,
				"ProviderKey":   key,
				"ProviderName":  name,
				"ExtraLinkURL":  extraURL,
				"ExtraLinkText": extraText,
			})
			return
		}
		log.Printf("login orphan check failed for %s: %v", claims.UUID, err)
		render(w, "login.html", map[string]any{
			"BaseURL":       appBaseURL,
			"ProviderKey":   key,
			"ProviderName":  name,
			"ExtraLinkURL":  extraURL,
			"ExtraLinkText": extraText,
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
	uname := usernameFrom(r.Context())
	uid := uuidFrom(r.Context())

	authorized := false
	var err error
	if uname == "" && uid == "" {
		log.Printf("home: no username/uuid in session; treating as not authorized")
	} else {
		authorized, err = currentProvider.IsAuthorized(uid, uname)
		if err != nil {
			log.Printf("home authz check failed for %s (%s): %v", uname, uid, err)
		}
	}

	// Opportunistic upsert ONLY when authorized (keeps DB lean)
	if authorized {
		_, _ = upsertUser(User{
			Username:    uname,
			MediaUUID:   nullStringFrom(uid),
			MediaAccess: true,
		})
	}

	// Use env-cased name for display
	_, providerDisplay := providerUI()
	extraURL, extraText := getExtraLink()

	if authorized {
		render(w, "portal_authorized.html", map[string]any{
			"Username":      uname,
			"ProviderName":  providerDisplay, // exact casing
			"ExtraLinkURL":  extraURL,
			"ExtraLinkText": extraText,
		})
		return
	}

	// Unauthorized page: build mailto params from env
	email, subj, subjQP := getRequestAccess(providerDisplay)
	render(w, "portal_unauthorized.html", map[string]any{
		"Username":         uname,
		"ProviderName":     providerDisplay, // exact casing
		"RequestEmail":     email,
		"RequestSubject":   subj,
		"RequestSubjectQP": subjQP,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}