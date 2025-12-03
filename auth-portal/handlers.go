package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	loginTemplate     = "login.html"
	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"
)

// providerUI returns the provider key used by code ("plex"/"emby")
// and the display name shown in templates.
func providerUI() (key, display string) {
	key = mediaProviderKey
	display = mediaProviderDisplay
	if key == "" && currentProvider != nil {
		key = currentProvider.Name()
	}
	if key == "" {
		key = "plex"
	}
	if display == "" {
		display = providerCanonicalDisplay(key)
	}
	return
}

// live getters read the current runtime configuration each request.
func extraLink() (urlStr, text string) {
	cfg := currentRuntimeConfig().AppSettings
	return sanitizeDisplayURL(cfg.LoginExtraLinkURL), strings.TrimSpace(cfg.LoginExtraLinkText)
}

func getRequestAccess(providerDisplay string) (email, subj, subjQP string) {
	cfg := currentRuntimeConfig().AppSettings
	email = sanitizeMailAddress(cfg.UnauthRequestEmail)
	if email == "" {
		email = "admin@example.com"
	}
	subj = strings.TrimSpace(cfg.UnauthRequestSubject)
	if subj == "" {
		subj = providerDisplay + " Access Request"
	}
	subjQP = url.QueryEscape(subj)
	return
}

func sanitizeDisplayURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return u.String()
}

func sanitizeMailAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(addr.Address)
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	key, name := providerUI()
	extraURL, extraText := extraLink()

	// If no session, show login page right away.
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		render(w, loginTemplate, map[string]any{
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
	}, jwt.WithValidMethods(allowedJWTAlgs))
	if err != nil || !tok.Valid {
		clearSessionCookie(w)
		render(w, loginTemplate, map[string]any{
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
		render(w, loginTemplate, map[string]any{
			"BaseURL":       appBaseURL,
			"ProviderKey":   key,
			"ProviderName":  name,
			"ExtraLinkURL":  extraURL,
			"ExtraLinkText": extraText,
		})
		return
	}

	if _, err := userByUUID(claims.UUID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			clearSessionCookie(w)
			render(w, loginTemplate, map[string]any{
				"BaseURL":       appBaseURL,
				"ProviderKey":   key,
				"ProviderName":  name,
				"ExtraLinkURL":  extraURL,
				"ExtraLinkText": extraText,
			})
			return
		}
		log.Printf("login orphan check failed for %s: %v", claims.UUID, err)
		render(w, loginTemplate, map[string]any{
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
	w.Header().Set(headerContentType, contentTypeJSON)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username": usernameFrom(r.Context()),
		"uuid":     uuidFrom(r.Context()),
		"admin":    adminFrom(r.Context()),
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
		Admin           bool   `json:"admin"`
	}

	key, display := providerUI()
	out := resp{OK: true, Provider: key, ProviderDisplay: display, LoginPath: "/auth/start-web"}

	ident := extractSessionIdentity(r)
	supplementIdentityFromContext(&ident, r.Context())

	if ident.Username == "" && ident.UUID == "" {
		w.Header().Set(headerContentType, contentTypeJSON)
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	out.Authenticated = true
	out.Username = ident.Username
	out.UUID = ident.UUID
	out.IssuedAt = ident.IssuedAt
	out.Expiry = ident.Expiry
	out.Admin = ident.Admin || adminFrom(r.Context())

	if authorized, err := currentProvider.IsAuthorized(ident.UUID, ident.Username); err != nil {
		log.Printf("whoami authz check failed for %s (%s): %v", ident.Username, ident.UUID, err)
	} else {
		out.MediaAccess = authorized
	}

	if ident.UUID != "" {
		if u, err := getUserByUUIDPreferred(ident.UUID); err == nil {
			if u.Email.Valid {
				out.Email = strings.TrimSpace(u.Email.String)
			}
		} else {
			log.Printf("whoami: user lookup failed for %s: %v", ident.UUID, err)
		}
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	_ = json.NewEncoder(w).Encode(out)
}

type sessionIdentity struct {
	Username string
	UUID     string
	Admin    bool
	IssuedAt string
	Expiry   string
}

func extractSessionIdentity(r *http.Request) sessionIdentity {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return sessionIdentity{}
	}
	tok, err := jwt.ParseWithClaims(
		c.Value,
		&sessionClaims{},
		func(t *jwt.Token) (interface{}, error) { return sessionSecret, nil },
		jwt.WithValidMethods(allowedJWTAlgs),
	)
	if err != nil || !tok.Valid {
		return sessionIdentity{}
	}
	claims, ok := tok.Claims.(*sessionClaims)
	if !ok {
		return sessionIdentity{}
	}
	ident := sessionIdentity{
		Username: claims.Username,
		UUID:     claims.UUID,
		Admin:    claims.Admin,
	}
	if claims.IssuedAt != nil {
		ident.IssuedAt = claims.IssuedAt.Time.Format(time.RFC3339)
	}
	if claims.ExpiresAt != nil {
		ident.Expiry = claims.ExpiresAt.Time.Format(time.RFC3339)
	}
	return ident
}

func supplementIdentityFromContext(ident *sessionIdentity, ctx context.Context) {
	if ident.Username == "" && ident.UUID == "" {
		ident.Username = usernameFrom(ctx)
		ident.UUID = uuidFrom(ctx)
	}
	if !ident.Admin {
		ident.Admin = adminFrom(ctx)
	}
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
		if _, err := upsertUser(User{
			Username:    uname,
			MediaUUID:   nullStringFrom(uid),
			MediaAccess: true,
		}); err != nil {
			log.Printf("home: upsert user failed for %s (%s): %v", uname, uid, err)
		}
	}

	// Use env-cased name for display
	_, providerDisplay := providerUI()
	extraURL, extraText := extraLink()

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

	if mfaEnforceForAllUsers {
		enabled, checkErr := userHasMFAEnabled(claims.UUID, claims.Username)
		if checkErr != nil {
			log.Printf("mfa challenge: enforcement lookup failed for %s (%s): %v", strings.TrimSpace(claims.Username), strings.TrimSpace(claims.UUID), checkErr)
		} else if !enabled {
			http.Redirect(w, r, "/mfa/enroll?pending=1", http.StatusFound)
			return
		}
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
