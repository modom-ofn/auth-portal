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
	"time"
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
		case "emby", "emby-connect", "embyconnect", "emby_connect":
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

// whoamiHandler returns a normalized identity payload for the frontend.
// It is safe to call without an authenticated session; in that case
// it returns authenticated=false along with provider info so the UI can
// render the correct login button.
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	type resp struct {
		OK              bool   `json:"ok"`
		Authenticated   bool   `json:"authenticated"`
		Provider        string `json:"provider"`
		ProviderDisplay string `json:"providerDisplay"`
		Username        string `json:"username,omitempty"`
		UUID            string `json:"uuid,omitempty"`
		Email           string `json:"email,omitempty"`
		MediaAccess     bool   `json:"mediaAccess"`
		LoginPath       string `json:"loginPath"`
		IssuedAt        string `json:"issuedAt,omitempty"`
		Expiry          string `json:"expiry,omitempty"`
	}

	key, display := providerUI()
	out := resp{OK: true, Provider: key, ProviderDisplay: display, LoginPath: "/auth/start-web"}

	// Try to extract identity from session cookie first
	var uname, uid string
	var issuedAtStr, expiryStr string
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if tok, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) { return sessionSecret, nil }); err == nil && tok.Valid {
			if claims, ok := tok.Claims.(*sessionClaims); ok {
				uname = claims.Username
				uid = claims.UUID
				if claims.IssuedAt != nil {
					issuedAtStr = claims.IssuedAt.Time.Format(time.RFC3339)
				}
				if claims.ExpiresAt != nil {
					expiryStr = claims.ExpiresAt.Time.Format(time.RFC3339)
				}
			}
		}
	}
	// Fallback to context (if this handler is ever wrapped by authMiddleware)
	if uname == "" && uid == "" {
		uname = usernameFrom(r.Context())
		uid = uuidFrom(r.Context())
	}

	if uname == "" && uid == "" {
		// No session; return provider info only
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	out.Authenticated = true
	out.Username = uname
	out.UUID = uid
	out.IssuedAt = issuedAtStr
	out.Expiry = expiryStr

	// Authorization check (provider-specific rules)
	authorized, err := currentProvider.IsAuthorized(uid, uname)
	if err != nil {
		// Log but continue with best-effort
		log.Printf("whoami authz check failed for %s (%s): %v", uname, uid, err)
	}
	out.MediaAccess = authorized

	// Try to populate email from DB if present
	if uid != "" {
		if u, err := getUserByUUIDPreferred(uid); err == nil {
			if u.Email.Valid {
				out.Email = strings.TrimSpace(u.Email.String)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
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

func mfaChallengePage(w http.ResponseWriter, r *http.Request) {
	claims, err := pendingClaimsFromRequest(r)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			clearPendingMFACookie(w)
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	render(w, "mfa_challenge.html", map[string]any{
		"Username": strings.TrimSpace(claims.Username),
		"Issuer":   mfaIssuer,
	})
}
func mfaEnrollPage(w http.ResponseWriter, r *http.Request) {
	uname := strings.TrimSpace(usernameFrom(r.Context()))
	if uname == "" {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	render(w, "mfa_enroll.html", map[string]any{
		"Username": uname,
		"Issuer":   mfaIssuer,
	})
}
