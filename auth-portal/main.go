package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"

	// Adjust this import path to match your module name from go.mod
	// e.g., "github.com/modom-ofn/auth-portal/health" or "modom-ofn/auth-portal/health"
	"auth-portal/configstore"
	"auth-portal/health"
	"auth-portal/providers"
	"golang.org/x/time/rate"
)

var (
	db                                     *sql.DB
	configStore                            *configstore.Store
	tmpl                                   *template.Template
	sessionSecret                          = []byte(envOr("SESSION_SECRET", "dev-insecure-change-me"))
	appBaseURL                             = envOr("APP_BASE_URL", "http://localhost:8089")
	plexOwnerToken                         = envOr("PLEX_OWNER_TOKEN", "")
	plexServerMachineID                    = envOr("PLEX_SERVER_MACHINE_ID", "")
	plexServerName                         = envOr("PLEX_SERVER_NAME", "")
	embyServerURL                          = envOr("EMBY_SERVER_URL", "http://localhost:8096")
	embyAppName                            = envOr("EMBY_APP_NAME", "AuthPortal")
	embyAppVersion                         = envOr("EMBY_APP_VERSION", "2.0.0")
	embyAPIKey                             = envOr("EMBY_API_KEY", "")
	embyOwnerUsername                      = envOr("EMBY_OWNER_USERNAME", "")
	embyOwnerID                            = envOr("EMBY_OWNER_ID", "")
	jellyfinServerURL                      = envOr("JELLYFIN_SERVER_URL", "http://localhost:8096")
	jellyfinAppName                        = envOr("JELLYFIN_APP_NAME", "AuthPortal")
	jellyfinAppVersion                     = envOr("JELLYFIN_APP_VERSION", "2.0.0")
	jellyfinAPIKey                         = envOr("JELLYFIN_API_KEY", "")
	mediaServerSelection                   = strings.TrimSpace(os.Getenv("MEDIA_SERVER"))
	mediaProviderKey, mediaProviderDisplay = resolveProviderSelection(mediaServerSelection)
	oidcSigningKeyPath                     = strings.TrimSpace(os.Getenv("OIDC_SIGNING_KEY_PATH"))
	oidcSigningKeyPEM                      = strings.TrimSpace(os.Getenv("OIDC_SIGNING_KEY"))
	oidcIssuerOverride                     = strings.TrimSpace(os.Getenv("OIDC_ISSUER"))

	// MFA configuration
	mfaIssuer             = envOr("MFA_ISSUER", "AuthPortal")
	mfaEnrollmentEnabled  = envBool("MFA_ENABLE", true)
	mfaEnforceForAllUsers = envBool("MFA_ENFORCE", false)

	// Optional extra link on the login page
	loginExtraLinkURL  = envOr("LOGIN_EXTRA_LINK_URL", "/some-internal-app")
	loginExtraLinkText = envOr("LOGIN_EXTRA_LINK_TEXT", "Open Internal App")

	// Unauthorized-page "Request Access" mailto link (optional)
	unauthRequestEmail   = envOr("UNAUTH_REQUEST_EMAIL", "admin@example.com")
	unauthRequestSubject = envOr("UNAUTH_REQUEST_SUBJECT", "Request Access")

	// Provider selected at startup (plex default; emby and jellyfin are distinct)
	currentProvider providers.MediaProvider

	// Session TTLs & flags
	sessionSameSite              = parseSameSite(os.Getenv("SESSION_SAMESITE"), http.SameSiteLaxMode)
	sessionTTL                   = parseDurationOr(os.Getenv("SESSION_TTL"), 24*time.Hour) // authorized sessions
	forceSecureCookie            = os.Getenv("FORCE_SECURE_COOKIE") == "1"                 // force 'Secure' even if APP_BASE_URL is http
	sessionCookieDomain          = strings.TrimSpace(os.Getenv("SESSION_COOKIE_DOMAIN"))
	sessionSameSiteWarningLogged bool
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func init() {
	ensureMFAConsistency()
}

// pickProvider selects the active media provider using the canonical key.
func pickProvider(selection string) providers.MediaProvider {
	switch key := strings.ToLower(strings.TrimSpace(selection)); key {
	case "jellyfin":
		return providers.JellyfinProvider{}
	case "emby":
		return providers.EmbyProvider{}
	case "emby-connect", "embyconnect", "emby_connect":
		log.Printf("Provider key %q no longer selects Emby Connect; using standard Emby provider", selection)
		return providers.EmbyProvider{}
	case "plex", "":
		return providers.PlexProvider{}
	default:
		log.Printf("Unknown provider %q; defaulting to plex", selection)
		return providers.PlexProvider{}
	}
}

// --- Health check helpers (minimal, local to main.go) ---
func dbChecker(db *sql.DB) health.Checker {
	return func(ctx context.Context) error {
		if db == nil {
			return errors.New("db not initialized")
		}
		ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		return db.PingContext(ctx)
	}
}

func main() {
	// ---- DB ----
	dsn := os.Getenv("DATABASE_URL")

	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	var err error
	db, err = sql.Open("postgres", dsn)

	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("DB ping error: %v", err)
	}

	if err = createSchema(); err != nil {
		log.Fatalf("Schema error: %v", err)
	}

	defaultSections, err := runtimeConfigDefaults()
	if err != nil {
		log.Fatalf("Config defaults error: %v", err)
	}

	configStore, err = configstore.New(db, configstore.Options{
		Defaults: defaultSections,
	})
	if err != nil {
		log.Fatalf("Config store init error: %v", err)
	}

	runtimeCfg, err := loadRuntimeConfig(configStore)
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}
	applyRuntimeConfig(runtimeCfg)

	if err := bootstrapAdminUsers(); err != nil {
		log.Printf("Admin bootstrap encountered issues: %v", err)
	}

	if err := initOIDCSigningKey(); err != nil {
		log.Fatalf("OIDC init error: %v", err)
	}

	snap := configStore.Snapshot()
	log.Printf("Config store loaded with %d items", snap.TotalItems())

	// ---- Templates ----
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	// ---- Provider configuration (DI init) ----
	providers.Init(providers.ProviderDeps{
		PlexOwnerToken:      plexOwnerToken,
		PlexServerMachineID: plexServerMachineID,
		PlexServerName:      plexServerName,
		EmbyServerURL:       embyServerURL,
		EmbyAppName:         embyAppName,
		EmbyAppVersion:      embyAppVersion,
		EmbyAPIKey:          embyAPIKey,
		EmbyOwnerUsername:   embyOwnerUsername,
		EmbyOwnerID:         embyOwnerID,
		JellyfinServerURL:   jellyfinServerURL,
		JellyfinAppName:     jellyfinAppName,
		JellyfinAppVersion:  jellyfinAppVersion,
		JellyfinAPIKey:      jellyfinAPIKey,
		UpsertUser: func(u providers.User) error {
			_, err := upsertUserIdentity(
				u.Username,
				u.Email,
				strings.TrimSpace(u.Provider),
				u.MediaUUID,
				u.MediaToken,
				u.MediaAccess,
			)
			return err
		},
		GetUserByUUID: func(uuid string) (providers.User, error) {
			u, err := getUserByUUIDPreferred(uuid)
			if err != nil {
				return providers.User{}, err
			}
			return providers.User{
				Username:    u.Username,
				Email:       u.Email.String,
				MediaUUID:   u.MediaUUID.String,
				MediaToken:  u.MediaToken.String,
				MediaAccess: u.MediaAccess,
			}, nil
		},
		SetUserMediaAccessByUsername: setUserMediaAccessByUsername,
		FinalizeLogin:                finalizeLoginSession,
		SetSessionCookie:             setSessionCookie,
		SetTempSessionCookie:         setTempSessionCookie,
		SealToken:                    SealToken,
		Debugf:                       Debugf,
		Warnf:                        Warnf,
	})

	// ---- Provider ----
	currentProvider = pickProvider(mediaProviderKey)
	log.Printf("AuthPortal using provider: %s", currentProvider.Name())

	// ---- Router ----
	r := mux.NewRouter()

	// Rate limiters for auth-sensitive routes
	loginLimiter := newIPRateLimiter(rate.Every(6*time.Second), 5, 15*time.Minute)
	mfaLimiter := newIPRateLimiter(rate.Every(12*time.Second), 3, 15*time.Minute)

	// Static assets
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public
	r.HandleFunc("/", loginPageHandler).Methods("GET")
	r.HandleFunc("/whoami", whoamiHandler).Methods("GET")
	r.HandleFunc("/mfa/challenge", mfaChallengePage).Methods("GET")
	r.Handle("/mfa/challenge/verify", requireSameOrigin(rateLimitMiddleware(mfaLimiter, http.HandlerFunc(mfaChallengeVerifyHandler)))).Methods("POST")
	enrollmentPageGuard := requireSessionOrPending(true)
	enrollmentAPIGuard := requireSessionOrPending(false)

	r.Handle("/mfa/enroll", enrollmentPageGuard(http.HandlerFunc(mfaEnrollPage))).Methods("GET")
	r.Handle("/mfa/enroll/status", enrollmentAPIGuard(http.HandlerFunc(mfaEnrollmentStatusHandler))).Methods("GET")

	// Provider routes (v2 adapter wraps legacy providers and returns responses we write).
	v2 := providers.AdaptV2(currentProvider)

	if err := v2.Health(); err != nil {
		log.Printf("Provider health warning: %v", err)
	}

	startWebHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, _ := v2.Start(r.Context(), r)
		providers.WriteHTTPResult(w, res)
	})
	startWebLimited := rateLimitMiddleware(loginLimiter, startWebHandler)
	r.Handle("/auth/start-web", startWebLimited).Methods("GET")
	r.Handle("/auth/start-web", requireSameOrigin(startWebLimited)).Methods("POST")

	forwardHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if op, ok := currentProvider.(providers.OutcomeProvider); ok {
			out, resp, err := op.CompleteOutcome(r.Context(), r)
			if resp != nil {
				providers.WriteHTTPResult(w, *resp)
				return
			}
			if err != nil {
				http.Error(w, "Auth failed", http.StatusUnauthorized)
				return
			}
			if providers.UpsertUser != nil {
				_ = providers.UpsertUser(providers.User{
					Username:    out.Username,
					Email:       out.Email,
					MediaUUID:   out.MediaUUID,
					MediaToken:  out.SealedToken,
					MediaAccess: out.Authorized,
				})
			}

			requiresMFA := false
			if out.Authorized {
				if providers.FinalizeLogin != nil {
					var finalizeErr error
					requiresMFA, finalizeErr = providers.FinalizeLogin(w, out.MediaUUID, out.Username)
					if finalizeErr != nil {
						http.Error(w, "Login finalization failed", http.StatusInternalServerError)
						return
					}
				} else {
					_ = providers.SetSessionCookie(w, out.MediaUUID, out.Username)
				}
			} else {
				_ = providers.SetTempSessionCookie(w, out.MediaUUID, out.Username)
			}

			prov := out.Provider
			if prov == "" {
				prov = v2.Name()
			}

			w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)

			redirect := "/home"
			message := "Signed in - you can close this window."
			if requiresMFA {
				redirect = "/mfa/challenge"
				message = "Continue in the main window to finish multi-factor authentication."
			}

			payload := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><title>Signed in - AuthPortal</title>`+
				`<body style="font-family:system-ui;padding:2rem"><h1>%s</h1>`+
				`<script>try{if(window.opener&&!window.opener.closed){window.opener.postMessage({ok:true,type:"%s",redirect:"%s",mfa:%t},window.location.origin)}}catch(e){};setTimeout(()=>{try{window.close()}catch(e){}},600);</script>`+
				`</body>`, template.HTMLEscapeString(message), prov+"-auth", redirect, requiresMFA)
			_, _ = w.Write([]byte(payload))
			return
		}

		res, _ := v2.Complete(r.Context(), r)
		providers.WriteHTTPResult(w, res)
	})
	forwardLimited := rateLimitMiddleware(loginLimiter, forwardHandler)
	r.Handle("/auth/forward", forwardLimited).Methods("GET")
	r.Handle("/auth/forward", requireSameOrigin(forwardLimited)).Methods("POST")

	// Plex fallback: JSON poll to complete auth if forwardUrl navigation fails
	r.Handle("/auth/poll", rateLimitMiddleware(loginLimiter, http.HandlerFunc(providers.PlexPoll))).Methods("GET")

	// Logout (protect with a simple same-origin check)
	r.Handle("/logout", requireSameOrigin(rateLimitMiddleware(loginLimiter, http.HandlerFunc(logoutHandler)))).Methods("POST")

	// Protected
	r.Handle("/home", authMiddleware(http.HandlerFunc(homeHandler))).Methods("GET")
	r.Handle("/me", authMiddleware(http.HandlerFunc(meHandler))).Methods("GET")
	r.Handle("/mfa/enroll/start", enrollmentAPIGuard(requireSameOrigin(rateLimitMiddleware(mfaLimiter, http.HandlerFunc(mfaEnrollmentStartHandler))))).Methods("POST")
	r.Handle("/mfa/enroll/verify", enrollmentAPIGuard(requireSameOrigin(rateLimitMiddleware(mfaLimiter, http.HandlerFunc(mfaEnrollmentVerifyHandler))))).Methods("POST")

	// OIDC discovery endpoints
	r.HandleFunc("/.well-known/openid-configuration", oidcDiscoveryHandler).Methods("GET")
	r.HandleFunc("/oidc/jwks.json", oidcJWKSHandler).Methods("GET")

	adminProtected := func(h http.Handler) http.Handler {
		return authMiddleware(requireAdmin(h))
	}
	adminAPI := r.PathPrefix("/api/admin").Subrouter()
	adminAPI.Handle("/config", adminProtected(http.HandlerFunc(adminConfigGetHandler))).Methods("GET")
	adminAPI.Handle("/config/{section}", adminProtected(http.HandlerFunc(adminConfigUpdateHandler))).Methods("PUT")
	adminAPI.Handle("/config/history/{section}", adminProtected(http.HandlerFunc(adminConfigHistoryHandler))).Methods("GET")
	r.Handle("/admin", adminProtected(http.HandlerFunc(adminPageHandler))).Methods("GET")

	// --- Health endpoints ---
	r.HandleFunc("/healthz", health.LivenessHandler()).Methods("GET")

	readyChecks := map[string]health.Checker{
		"db": dbChecker(db),
	}
	r.HandleFunc("/startupz", health.ReadinessHandler(readyChecks)).Methods("GET")
	r.HandleFunc("/readyz", health.ReadinessHandler(readyChecks)).Methods("GET")

	// Wrap with security headers and request logging
	handler := withSecurityHeaders(WithRequestLogging(r))
	log.Printf("Log level: %s", strings.ToUpper(os.Getenv("LOG_LEVEL")))
	log.Println("Starting AuthPortal on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic hardening
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Global CSP (the /auth/forward response can set its own relaxed CSP for inline JS)
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: https://plex.tv https://api.qrserver.com; style-src 'self' 'unsafe-inline'; script-src 'self'")

		// HSTS only if base URL is HTTPS or you know you're behind TLS
		if strings.HasPrefix(strings.ToLower(appBaseURL), "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=86400; includeSubDomains; preload")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Session (JWT in HTTP-only cookie) ----------
const (
	sessionCookie    = "authportal_session"
	pendingMFACookie = "authportal_mfa_pending"
)

var pendingMFATTL = 10 * time.Minute

type sessionClaims struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Admin    bool   `json:"admin,omitempty"`
	jwt.RegisteredClaims
}

type pendingMFAClaims struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func cookieSettings() (http.SameSite, bool) {
	sameSite := sessionSameSite
	secure := forceSecureCookie || strings.HasPrefix(strings.ToLower(appBaseURL), "https://")
	if sameSite == http.SameSiteNoneMode && !secure {
		if !sessionSameSiteWarningLogged {
			log.Println("SESSION_SAMESITE=none requires Secure cookies; falling back to SameSite=Lax until HTTPS or FORCE_SECURE_COOKIE=1")
			sessionSameSiteWarningLogged = true
		}
		sameSite = http.SameSiteLaxMode
	}
	return sameSite, secure
}

func setSessionCookieWithTTL(w http.ResponseWriter, uuid, username string, ttl time.Duration) error {
	now := time.Now()

	isAdmin, err := userIsAdmin(uuid, username)
	if err != nil {
		return err
	}

	claims := sessionClaims{
		UUID:     uuid,
		Username: username,
		Admin:    isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-portal-go",
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sessionSecret)
	if err != nil {
		return err
	}

	sameSite, secure := cookieSettings()
	clearPendingMFACookie(w)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    signed,
		Domain:   sessionCookieDomain,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})

	return nil
}

// Normal (authorized) session
func setSessionCookie(w http.ResponseWriter, uuid, username string) error {
	return setSessionCookieWithTTL(w, uuid, username, sessionTTL)
}

// Short-lived (e.g., for temporary/unauthorized states if you choose to use it)
func setTempSessionCookie(w http.ResponseWriter, uuid, username string) error {
	return setSessionCookieWithTTL(w, uuid, username, 5*time.Minute)
}

func expireSessionCookieOnly(w http.ResponseWriter) {
	sameSite, secure := cookieSettings()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Domain:   sessionCookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})
}

func setPendingMFACookie(w http.ResponseWriter, uuid, username string) error {
	now := time.Now()

	claims := pendingMFAClaims{
		UUID:     uuid,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-portal-go",
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(now.Add(pendingMFATTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sessionSecret)
	if err != nil {
		return err
	}

	sameSite, secure := cookieSettings()
	http.SetCookie(w, &http.Cookie{
		Name:     pendingMFACookie,
		Value:    signed,
		Domain:   sessionCookieDomain,
		Path:     "/",
		MaxAge:   int(pendingMFATTL.Seconds()),
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})

	return nil
}

func clearPendingMFACookie(w http.ResponseWriter) {
	sameSite, secure := cookieSettings()
	http.SetCookie(w, &http.Cookie{
		Name:     pendingMFACookie,
		Value:    "",
		Domain:   sessionCookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})
}

func pendingClaimsFromRequest(r *http.Request) (pendingMFAClaims, error) {
	c, err := r.Cookie(pendingMFACookie)

	if err != nil {
		return pendingMFAClaims{}, err
	}

	tok, err := jwt.ParseWithClaims(c.Value, &pendingMFAClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	})

	if err != nil || tok == nil {
		return pendingMFAClaims{}, err
	}

	claims, ok := tok.Claims.(*pendingMFAClaims)
	if !ok || !tok.Valid {
		return pendingMFAClaims{}, errors.New("invalid pending MFA token")
	}

	if strings.TrimSpace(claims.UUID) == "" || strings.TrimSpace(claims.Username) == "" {
		return pendingMFAClaims{}, errors.New("empty pending claims")
	}
	return *claims, nil
}

func hasPendingMFACookie(r *http.Request) bool {
	_, err := pendingClaimsFromRequest(r)
	return err == nil
}

func finalizeLoginSession(w http.ResponseWriter, uuid, username string) (bool, error) {
	enabled, err := userHasMFAEnabled(uuid, username)
	if err != nil {
		return false, err
	}

	if !enabled {
		if mfaEnforceForAllUsers {
			expireSessionCookieOnly(w)
			if err := setPendingMFACookie(w, uuid, username); err != nil {
				return false, err
			}
			return true, nil
		}

		clearPendingMFACookie(w)
		if err := setSessionCookie(w, uuid, username); err != nil {
			return false, err
		}
		return false, nil
	}

	expireSessionCookieOnly(w)

	if err := setPendingMFACookie(w, uuid, username); err != nil {
		return false, err
	}
	return true, nil
}

func clearSessionCookie(w http.ResponseWriter) {
	clearPendingMFACookie(w)
	expireSessionCookieOnly(w)
}

func requireSessionOrPending(redirectOnFail bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isAdmin := adminFrom(r.Context())
			var (
				username string
				uuid     string
			)

			if c, err := r.Cookie(sessionCookie); err == nil && strings.TrimSpace(c.Value) != "" {
				tok, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
					return sessionSecret, nil
				})
				if err == nil && tok != nil && tok.Valid {
					if claims, ok := tok.Claims.(*sessionClaims); ok {
						username = strings.TrimSpace(claims.Username)
						uuid = strings.TrimSpace(claims.UUID)
						isAdmin = claims.Admin
					}
				}
				if username == "" || uuid == "" {
					expireSessionCookieOnly(w)
				}
			}

			if username == "" || uuid == "" {
				if claims, err := pendingClaimsFromRequest(r); err == nil {
					username = strings.TrimSpace(claims.Username)
					uuid = strings.TrimSpace(claims.UUID)
				}
			}

			if username == "" || uuid == "" {
				if redirectOnFail {
					http.Redirect(w, r, "/", http.StatusFound)
				} else {
					respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session required"})
				}
				return
			}

			ctx := withUsername(r.Context(), username)
			ctx = withUUID(ctx, uuid)
			ctx = withAdmin(ctx, isAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)

		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		token, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
			return sessionSecret, nil
		})

		if err != nil || !token.Valid {
			clearSessionCookie(w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if claims, ok := token.Claims.(*sessionClaims); ok {
			ctx := withUsername(r.Context(), claims.Username)
			ctx = withUUID(ctx, claims.UUID)
			ctx = withAdmin(ctx, claims.Admin)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func hasValidSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	token, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	})
	return err == nil && token.Valid
}

// ---------- CSRF-lite for state-changing routes ----------
func requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow safe methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Allow /logout explicitly to avoid Origin/Referer edge cases.
		if r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// Build allowed origin and host allowlists derived from config and proxy headers.
		allowed := make(map[string]struct{}, 4)
		allowedHosts := make(map[string]struct{}, 4)

		firstHeaderValue := func(v string) string {
			if v == "" {
				return ""
			}
			parts := strings.Split(v, ",")
			if len(parts) == 0 {
				return ""
			}
			return strings.TrimSpace(parts[0])
		}

		addHost := func(h string) {
			h = strings.TrimSpace(h)
			if h == "" {
				return
			}
			lower := strings.ToLower(h)
			allowedHosts[lower] = struct{}{}
			if hostOnly, _, err := net.SplitHostPort(lower); err == nil {
				allowedHosts[hostOnly] = struct{}{}
			} else {
				if strings.HasSuffix(lower, ":80") {
					allowedHosts[strings.TrimSuffix(lower, ":80")] = struct{}{}
				}
				if strings.HasSuffix(lower, ":443") {
					allowedHosts[strings.TrimSuffix(lower, ":443")] = struct{}{}
				}
			}
		}

		addOrigin := func(scheme, host string) {
			scheme = strings.TrimSpace(scheme)
			host = strings.TrimSpace(host)
			if scheme == "" || host == "" {
				return
			}
			scheme = strings.ToLower(scheme)
			lowerHost := strings.ToLower(host)
			allowed[scheme+"://"+lowerHost] = struct{}{}
			addHost(host)
			if hostOnly, _, err := net.SplitHostPort(lowerHost); err == nil {
				allowed[scheme+"://"+hostOnly] = struct{}{}
				addHost(hostOnly)
			} else {
				if strings.HasSuffix(lowerHost, ":80") {
					trimmed := strings.TrimSuffix(lowerHost, ":80")
					allowed[scheme+"://"+trimmed] = struct{}{}
					addHost(trimmed)
				}
				if strings.HasSuffix(lowerHost, ":443") {
					trimmed := strings.TrimSuffix(lowerHost, ":443")
					allowed[scheme+"://"+trimmed] = struct{}{}
					addHost(trimmed)
				}
			}
		}

		// (1) APP_BASE_URL origin
		if u, err := url.Parse(appBaseURL); err == nil && u.Scheme != "" && u.Host != "" {
			addOrigin(u.Scheme, u.Host)
		}

		// (2) origin derived from request / proxy headers
		proto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))
		host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = r.Host
		}

		if proto == "" {
			if r.TLS != nil {
				proto = "https"
			} else {
				proto = "http"
			}
		}

		proto = strings.ToLower(strings.TrimSpace(proto))
		host = strings.TrimSpace(host)
		addOrigin(proto, host)

		if rHost := strings.TrimSpace(r.Host); rHost != "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			addOrigin(scheme, rHost)
		}

		reqHostKey := strings.ToLower(host)
		reqOrigin := proto + "://" + reqHostKey

		// Helper to compare only scheme://host[:port] (ignores scheme mismatches for same host)
		matchesAllowed := func(hdr string) bool {
			if hdr == "" {
				return false
			}
			u, err := url.Parse(hdr)
			if err != nil || u.Host == "" {
				return false
			}
			scheme := strings.ToLower(u.Scheme)
			hostKey := strings.ToLower(u.Host)
			if scheme != "" {
				if _, ok := allowed[scheme+"://"+hostKey]; ok {
					return true
				}
			}
			if hostOnly, _, err := net.SplitHostPort(hostKey); err == nil {
				if scheme != "" {
					if _, ok := allowed[scheme+"://"+hostOnly]; ok {
						return true
					}
				}
				if _, ok := allowedHosts[hostOnly]; ok {
					return true
				}
			}
			if _, ok := allowedHosts[hostKey]; ok {
				return true
			}
			return false
		}

		origin := r.Header.Get("Origin")
		referer := r.Header.Get("Referer")

		// Accept if either header matches an allowed origin.
		if matchesAllowed(origin) || matchesAllowed(referer) {
			next.ServeHTTP(w, r)
			return
		}

		// ...or if headers are missing but the request origin itself is allowed.
		if origin == "" && referer == "" {
			if _, ok := allowed[reqOrigin]; ok {
				next.ServeHTTP(w, r)
				return
			}
			if hostOnly, _, err := net.SplitHostPort(reqHostKey); err == nil {
				if _, ok := allowed[proto+"://"+hostOnly]; ok {
					next.ServeHTTP(w, r)
					return
				}
				if _, ok := allowedHosts[hostOnly]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}
			if reqHostKey != "" {
				if _, ok := allowedHosts[reqHostKey]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Error(w, "CSRF check failed", http.StatusForbidden)
	})
}

func parseSameSite(value string, def http.SameSite) http.SameSite {
	v := strings.TrimSpace(strings.ToLower(value))
	switch v {
	case "":
		return def
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		log.Printf("Unknown SESSION_SAMESITE value %q; using default", value)
		return def
	}
}

func parseDurationOr(s string, d time.Duration) time.Duration {
	if v, err := time.ParseDuration(s); err == nil {
		return v
	}
	return d
}
