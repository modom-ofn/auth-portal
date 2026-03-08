package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq" // register postgres driver

	// Adjust this import path to match your module name from go.mod
	// e.g., "github.com/modom-ofn/auth-portal/health" or "modom-ofn/auth-portal/health"
	"auth-portal/configstore"
	"auth-portal/health"
	"auth-portal/oauth"
	"auth-portal/providers"
	"golang.org/x/time/rate"
)

var (
	db                                     *sql.DB
	configStore                            *configstore.Store
	backupSvc                              *backupService
	sessionSecret                          []byte
	appBaseURL                             = envOr("APP_BASE_URL", "http://localhost:8089")
	appTimeZone                            = envOr("APP_TIMEZONE", "UTC")
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
	oauthService                           oauth.Service

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

	// Active provider is runtime-configurable and accessed per request.
	currentProvider atomic.Value // stores providers.MediaProvider

	// Session TTLs & flags
	sessionSameSite              = parseSameSite(os.Getenv("SESSION_SAMESITE"), http.SameSiteLaxMode)
	sessionTTL                   = parseDurationOr(os.Getenv("SESSION_TTL"), 24*time.Hour) // authorized sessions
	forceSecureCookie            = os.Getenv("FORCE_SECURE_COOKIE") == "1"                 // force 'Secure' even if APP_BASE_URL is http
	sessionCookieDomain          = strings.TrimSpace(os.Getenv("SESSION_COOKIE_DOMAIN"))
	sessionSameSiteWarningLogged bool
	forceHSTS                    = os.Getenv("FORCE_HSTS") == "1"
	appLocation                  = time.UTC
)

type providerState struct {
	provider providers.MediaProvider
}

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
	initSessionSecret()
	ensureMFAConsistency()
}

const minSessionSecretBytes = 32

var allowedJWTAlgs = []string{jwt.SigningMethodHS256.Alg()}

func initSessionSecret() {
	raw := os.Getenv("SESSION_SECRET")
	if strings.TrimSpace(raw) == "" {
		log.Fatal("SESSION_SECRET is required and must be at least 32 random bytes")
	}
	if raw == "dev-insecure-change-me" {
		log.Fatal("SESSION_SECRET must be changed from the default value")
	}
	if len(raw) < minSessionSecretBytes {
		log.Fatalf("SESSION_SECRET must be at least %d bytes (got %d)", minSessionSecretBytes, len(raw))
	}
	sessionSecret = []byte(raw)
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

func setCurrentProvider(p providers.MediaProvider) {
	if p == nil {
		return
	}
	currentProvider.Store(providerState{provider: p})
}

func activeProvider() providers.MediaProvider {
	if v := currentProvider.Load(); v != nil {
		if state, ok := v.(providerState); ok && state.provider != nil {
			return state.provider
		}
	}
	return pickProvider(mediaProviderKey)
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
	appTimeZone, appLocation = resolveLocation(appTimeZone)

	db = mustInitDB(os.Getenv("DATABASE_URL"))
	var runtimeCfg RuntimeConfig
	configStore, runtimeCfg = mustInitConfigStore(db)
	applyRuntimeConfig(runtimeCfg)

	backupSvc = mustInitBackupService(configStore)
	oauthService = newOAuthService()

	if err := bootstrapAdminUsers(); err != nil {
		log.Printf("Admin bootstrap encountered issues: %v", err)
	}

	mustInitOIDCSigningKey()
	logConfigSnapshot(configStore)

	initProviderDeps()
	setCurrentProvider(pickProvider(mediaProviderKey))
	log.Printf("AuthPortal using provider: %s", activeProvider().Name())

	router := buildRouter()
	startServer(router)
}

func resolveLocation(tz string) (string, *time.Location) {
	tzName := strings.TrimSpace(tz)
	if tzName == "" {
		tzName = "UTC"
	}
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		log.Printf("Invalid APP_TIMEZONE %q; defaulting to UTC: %v", tzName, err)
		return "UTC", time.UTC
	}
	return tzName, loc
}

func mustInitDB(dsn string) *sql.DB {
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	dbConn, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}
	if err := dbConn.Ping(); err != nil {
		log.Fatalf("DB ping error: %v", err)
	}
	// Set global so schema helpers that use package-level db can run safely.
	db = dbConn
	if err := createSchema(); err != nil {
		log.Fatalf("Schema error: %v", err)
	}
	return dbConn
}

func mustInitConfigStore(db *sql.DB) (*configstore.Store, RuntimeConfig) {
	defaultSections, err := runtimeConfigDefaults()
	if err != nil {
		log.Fatalf("Config defaults error: %v", err)
	}

	store, err := configstore.New(db, configstore.Options{Defaults: defaultSections})
	if err != nil {
		log.Fatalf("Config store init error: %v", err)
	}

	runtimeCfg, err := loadRuntimeConfig(store)
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}
	return store, runtimeCfg
}

func mustInitBackupService(store *configstore.Store) *backupService {
	backupDir := envOr("BACKUP_DIR", defaultBackupDirName)
	svc, err := newBackupService(store, backupDir)
	if err != nil {
		log.Fatalf("Backup service init error: %v", err)
	}
	return svc
}

func newOAuthService() oauth.Service {
	return oauth.Service{
		DB:              db,
		AuthCodeTTL:     5 * time.Minute,
		AccessTokenTTL:  sessionTTL,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
}

func mustInitOIDCSigningKey() {
	if err := initOIDCSigningKey(); err != nil {
		log.Fatalf("OIDC init error: %v", err)
	}
}

func logConfigSnapshot(store *configstore.Store) {
	if store == nil {
		return
	}
	snap := store.Snapshot()
	log.Printf("Config store loaded with %d items", snap.TotalItems())
}

func initProviderDeps() {
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
		SetUserAdminByUsername: func(username string, admin bool) error {
			return setUserAdminByUsername(username, admin, "provider-sync")
		},
		FinalizeLogin:        finalizeLoginSession,
		SetSessionCookie:     setSessionCookie,
		SetTempSessionCookie: setTempSessionCookie,
		SealToken:            SealToken,
		Debugf:               Debugf,
		Warnf:                Warnf,
	})
}

type routeLimiters struct {
	login    *ipRateLimiter
	mfa      *ipRateLimiter
	plexPoll *ipRateLimiter
}

func newRouteLimiters() routeLimiters {
	return routeLimiters{
		login:    newIPRateLimiter(rate.Every(6*time.Second), 5, 15*time.Minute),
		mfa:      newIPRateLimiter(rate.Every(12*time.Second), 3, 15*time.Minute),
		plexPoll: newIPRateLimiter(rate.Every(1*time.Second), 6, 10*time.Minute),
	}
}

func registerStaticAndBasicRoutes(r *mux.Router, lim routeLimiters) {
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.HandleFunc("/", loginPageHandler).Methods("GET")
	r.HandleFunc("/whoami", whoamiHandler).Methods("GET")
	r.HandleFunc("/mfa/challenge", mfaChallengePage).Methods("GET")
	r.Handle("/mfa/challenge/verify", requireSameOrigin(rateLimitMiddleware(lim.mfa, http.HandlerFunc(mfaChallengeVerifyHandler)))).Methods("POST")
}

func registerEnrollmentRoutes(r *mux.Router, lim routeLimiters) {
	enrollmentPageGuard := requireSessionOrPending(true)
	enrollmentAPIGuard := requireSessionOrPending(false)

	r.Handle("/mfa/enroll", enrollmentPageGuard(http.HandlerFunc(mfaEnrollPage))).Methods("GET")
	r.Handle("/mfa/enroll/status", enrollmentAPIGuard(http.HandlerFunc(mfaEnrollmentStatusHandler))).Methods("GET")
	r.Handle("/mfa/enroll/start", enrollmentAPIGuard(requireSameOrigin(rateLimitMiddleware(lim.mfa, http.HandlerFunc(mfaEnrollmentStartHandler))))).Methods("POST")
	r.Handle("/mfa/enroll/verify", enrollmentAPIGuard(requireSameOrigin(rateLimitMiddleware(lim.mfa, http.HandlerFunc(mfaEnrollmentVerifyHandler))))).Methods("POST")
}

func registerOIDCRoutes(r *mux.Router) {
	r.HandleFunc("/.well-known/openid-configuration", oidcDiscoveryHandler).Methods("GET")
	r.HandleFunc("/oidc/jwks.json", oidcJWKSHandler).Methods("GET")
	r.Handle("/oidc/authorize", authMiddleware(http.HandlerFunc(oidcAuthorizeHandler))).Methods("GET")
	r.Handle("/oidc/authorize/decision", authMiddleware(requireSameOrigin(http.HandlerFunc(oidcAuthorizeDecisionHandler)))).Methods("POST")
	r.HandleFunc("/oidc/token", oidcTokenHandler).Methods("POST")
	r.HandleFunc("/oidc/userinfo", oidcUserinfoHandler).Methods("GET")
}

func providerNameForCompletePage(out providers.AuthOutcome, v2 providers.MediaProviderV2) string {
	prov := out.Provider
	if prov == "" {
		prov = v2.Name()
	}
	return prov + "-auth"
}

func maybeUpsertProviderOutcomeUser(out providers.AuthOutcome) {
	if providers.UpsertUser == nil {
		return
	}
	provider := strings.TrimSpace(out.Provider)
	if provider == "" {
		// Fallback for older providers that might omit the field.
		switch {
		case strings.HasPrefix(strings.TrimSpace(out.MediaUUID), "plex-"):
			provider = "plex"
		case strings.HasPrefix(strings.TrimSpace(out.MediaUUID), "emby-"):
			provider = "emby"
		case strings.HasPrefix(strings.TrimSpace(out.MediaUUID), "jellyfin-"):
			provider = "jellyfin"
		}
	}
	if err := providers.UpsertUser(providers.User{
		Username:    out.Username,
		Email:       out.Email,
		MediaUUID:   out.MediaUUID,
		MediaToken:  out.SealedToken,
		MediaAccess: out.Authorized,
		Provider:    provider,
	}); err != nil {
		log.Printf("provider outcome upsert failed for %s (%s): %v", out.Username, out.MediaUUID, err)
	}
}

func finalizeProviderOutcomeSession(w http.ResponseWriter, out providers.AuthOutcome) (bool, error) {
	if out.Authorized {
		if providers.FinalizeLogin != nil {
			return providers.FinalizeLogin(w, out.MediaUUID, out.Username)
		}
		_ = providers.SetSessionCookie(w, out.MediaUUID, out.Username)
		return false, nil
	}
	_ = providers.SetTempSessionCookie(w, out.MediaUUID, out.Username)
	return false, nil
}

func completePageMessageAndRedirect(requiresMFA bool) (string, string) {
	if requiresMFA {
		return providers.PostAuthMessageContinueMFA, providers.PostAuthRedirectMFAChallenge
	}
	return providers.PostAuthMessageSignedIn, providers.PostAuthRedirectHome
}

func handleOutcomeProviderForward(w http.ResponseWriter, r *http.Request, v2 providers.MediaProviderV2, op providers.OutcomeProvider) bool {
	out, resp, err := op.CompleteOutcome(r.Context(), r)
	if resp != nil {
		providers.WriteHTTPResult(w, *resp)
		return true
	}
	if err != nil {
		http.Error(w, "Auth failed", http.StatusUnauthorized)
		return true
	}

	maybeUpsertProviderOutcomeUser(out)

	requiresMFA, finalizeErr := finalizeProviderOutcomeSession(w, out)
	if finalizeErr != nil {
		http.Error(w, "Login finalization failed", http.StatusInternalServerError)
		return true
	}

	message, redirect := completePageMessageAndRedirect(requiresMFA)
	providers.WriteAuthCompletePage(w, providers.AuthCompletePageOptions{
		Message:     message,
		Provider:    providerNameForCompletePage(out, v2),
		Redirect:    redirect,
		RequiresMFA: requiresMFA,
	})
	return true
}

func buildProviderStartHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v2 := providers.AdaptV2(activeProvider())
		res, err := v2.Start(r.Context(), r)
		if err != nil {
			log.Printf("provider start error: %v", err)
		}
		providers.WriteHTTPResult(w, res)
	})
}

func buildProviderForwardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := activeProvider()
		v2 := providers.AdaptV2(provider)
		if op, ok := provider.(providers.OutcomeProvider); ok {
			if handled := handleOutcomeProviderForward(w, r, v2, op); handled {
				return
			}
		}

		res, err := v2.Complete(r.Context(), r)
		if err != nil {
			log.Printf("provider complete error: %v", err)
		}
		providers.WriteHTTPResult(w, res)
	})
}

func registerProviderRoutes(r *mux.Router, lim routeLimiters) {
	v2 := providers.AdaptV2(activeProvider())
	if err := v2.Health(); err != nil {
		log.Printf("Provider health warning: %v", err)
	}

	startWebLimited := rateLimitMiddleware(lim.login, buildProviderStartHandler())
	r.Handle("/auth/start-web", startWebLimited).Methods("GET")
	r.Handle("/auth/start-web", requireSameOrigin(startWebLimited)).Methods("POST")

	forwardLimited := rateLimitMiddleware(lim.login, buildProviderForwardHandler())
	r.Handle("/auth/forward", forwardLimited).Methods("GET")
	r.Handle("/auth/forward", requireSameOrigin(forwardLimited)).Methods("POST")

	r.Handle("/auth/poll", rateLimitMiddleware(lim.plexPoll, http.HandlerFunc(providers.PlexPoll))).Methods("GET")
	r.Handle("/logout", requireSameOrigin(rateLimitMiddleware(lim.login, http.HandlerFunc(logoutHandler)))).Methods("POST")
}

func registerAuthenticatedRoutes(r *mux.Router) {
	r.Handle("/home", authMiddleware(http.HandlerFunc(homeHandler))).Methods("GET")
	r.Handle("/me", authMiddleware(http.HandlerFunc(meHandler))).Methods("GET")
}

func registerAdminRoutes(r *mux.Router) {
	adminProtected := func(h http.Handler) http.Handler {
		return authMiddleware(requireAdmin(h))
	}

	adminAPI := r.PathPrefix("/api/admin").Subrouter()
	adminAPI.Handle("/config", adminProtected(http.HandlerFunc(adminConfigGetHandler))).Methods("GET")
	adminAPI.Handle("/config/{section}", adminProtected(http.HandlerFunc(adminConfigUpdateHandler))).Methods("PUT")
	adminAPI.Handle("/config/history/{section}", adminProtected(http.HandlerFunc(adminConfigHistoryHandler))).Methods("GET")
	adminAPI.Handle("/oauth/clients", adminProtected(http.HandlerFunc(adminOAuthClientsList))).Methods("GET")
	adminAPI.Handle("/oauth/clients", adminProtected(http.HandlerFunc(adminOAuthClientCreate))).Methods("POST")
	adminAPI.Handle("/oauth/clients/{id}", adminProtected(http.HandlerFunc(adminOAuthClientUpdate))).Methods("PUT")
	adminAPI.Handle("/oauth/clients/{id}", adminProtected(http.HandlerFunc(adminOAuthClientDelete))).Methods("DELETE")
	adminAPI.Handle("/oauth/clients/{id}/rotate-secret", adminProtected(http.HandlerFunc(adminOAuthClientRotateSecret))).Methods("POST")
	adminAPI.Handle("/backups", adminProtected(http.HandlerFunc(adminBackupsListHandler))).Methods("GET")
	adminAPI.Handle("/backups", adminProtected(http.HandlerFunc(adminBackupsCreateHandler))).Methods("POST")
	adminAPI.Handle("/backups/schedule", adminProtected(http.HandlerFunc(adminBackupsScheduleUpdate))).Methods("PUT")
	adminAPI.Handle("/backups/{name}/restore", adminProtected(http.HandlerFunc(adminBackupsRestoreHandler))).Methods("POST")
	adminAPI.Handle("/backups/{name}", adminProtected(http.HandlerFunc(adminBackupsDownloadHandler))).Methods("GET")
	adminAPI.Handle("/backups/{name}", adminProtected(http.HandlerFunc(adminBackupsDeleteHandler))).Methods("DELETE")
	r.Handle("/admin", adminProtected(http.HandlerFunc(adminPageHandler))).Methods("GET")
}

func registerHealthRoutes(r *mux.Router) {
	r.HandleFunc("/healthz", health.LivenessHandler()).Methods("GET")
	readyChecks := map[string]health.Checker{
		"db": dbChecker(db),
	}
	r.HandleFunc("/startupz", health.ReadinessHandler(readyChecks)).Methods("GET")
	r.HandleFunc("/readyz", health.ReadinessHandler(readyChecks)).Methods("GET")
}

func buildRouter() *mux.Router {
	r := mux.NewRouter()
	limiters := newRouteLimiters()
	registerStaticAndBasicRoutes(r, limiters)
	registerEnrollmentRoutes(r, limiters)
	registerOIDCRoutes(r)
	registerProviderRoutes(r, limiters)
	registerAuthenticatedRoutes(r)
	registerAdminRoutes(r)
	registerHealthRoutes(r)
	return r
}

func startServer(router *mux.Router) {
	handler := withSecurityHeaders(WithRequestLogging(router))
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
		if strings.HasPrefix(strings.ToLower(appBaseURL), "https://") || forceHSTS {
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
	Version  int64  `json:"sessionVersion,omitempty"`
	jwt.RegisteredClaims
}

type pendingMFAClaims struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func validateSessionClaims(claims *sessionClaims) (bool, bool) {
	if claims == nil {
		return false, false
	}
	uuid := strings.TrimSpace(claims.UUID)
	username := strings.TrimSpace(claims.Username)
	if uuid == "" && username == "" {
		return false, false
	}
	isAdmin, version, err := userSessionState(uuid, username)
	if err != nil {
		return false, false
	}
	if version != claims.Version {
		return false, false
	}
	return true, isAdmin
}

func cookieSettings() (http.SameSite, bool) {
	sameSite := sessionSameSite
	secure := true
	if !strings.HasPrefix(strings.ToLower(appBaseURL), "https://") && !forceSecureCookie && !sessionSameSiteWarningLogged {
		log.Println("Warning: forcing Secure cookies; set APP_BASE_URL to https:// or enable FORCE_SECURE_COOKIE=1 to avoid cookie drop in HTTP-only setups")
		sessionSameSiteWarningLogged = true
	}
	// SameSite=None requires Secure; we already force Secure above.
	if sameSite == http.SameSiteNoneMode && !secure && !sessionSameSiteWarningLogged {
		log.Println("SESSION_SAMESITE=none requires Secure cookies; forcing Secure flag")
		sessionSameSiteWarningLogged = true
	}
	return sameSite, secure
}

func setSessionCookieWithTTL(w http.ResponseWriter, uuid, username string, ttl time.Duration) error {
	now := time.Now()

	isAdmin, sessionVersion, err := userSessionState(uuid, username)
	if err != nil {
		return err
	}

	claims := sessionClaims{
		UUID:     uuid,
		Username: username,
		Admin:    isAdmin,
		Version:  sessionVersion,
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
	}, jwt.WithValidMethods(allowedJWTAlgs))

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
			state := sessionStateFromRequest(w, r)
			if !state.authorized {
				state = pendingStateFromRequest(state, r)
			}

			if state.username == "" || state.uuid == "" || (!state.authorized && !state.pending) {
				if redirectOnFail {
					http.Redirect(w, r, "/", http.StatusFound)
				} else {
					respondJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session required"})
				}
				return
			}

			ctx := withUsername(r.Context(), state.username)
			ctx = withUUID(ctx, state.uuid)
			ctx = withAdmin(ctx, state.admin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type sessionState struct {
	username   string
	uuid       string
	admin      bool
	authorized bool
	pending    bool
}

func sessionStateFromRequest(w http.ResponseWriter, r *http.Request) sessionState {
	state := sessionState{admin: adminFrom(r.Context())}
	c, err := r.Cookie(sessionCookie)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return state
	}

	tok, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	}, jwt.WithValidMethods(allowedJWTAlgs))
	if err != nil || tok == nil || !tok.Valid {
		expireSessionCookieOnly(w)
		return state
	}

	claims, ok := tok.Claims.(*sessionClaims)
	if !ok {
		expireSessionCookieOnly(w)
		return state
	}

	if valid, adminFlag := validateSessionClaims(claims); valid {
		state.username = strings.TrimSpace(claims.Username)
		state.uuid = strings.TrimSpace(claims.UUID)
		state.admin = adminFlag
		state.authorized = adminFlag
		provider := activeProvider()
		if !adminFlag && provider != nil && state.uuid != "" {
			if ok, authErr := provider.IsAuthorized(state.uuid, state.username); authErr == nil {
				state.authorized = ok
			} else {
				log.Printf("requireSessionOrPending: authorization check failed for %s (%s): %v", state.username, state.uuid, authErr)
			}
		}
	} else {
		expireSessionCookieOnly(w)
	}
	return state
}

func pendingStateFromRequest(state sessionState, r *http.Request) sessionState {
	if state.authorized {
		return state
	}
	claims, err := pendingClaimsFromRequest(r)
	if err != nil {
		return state
	}
	state.username = strings.TrimSpace(claims.Username)
	state.uuid = strings.TrimSpace(claims.UUID)
	state.pending = true
	return state
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)

		if err != nil || c.Value == "" {
			http.Redirect(w, r, loginRedirectTarget(r), http.StatusFound)
			return
		}

		token, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
			return sessionSecret, nil
		}, jwt.WithValidMethods(allowedJWTAlgs))

		if err != nil || !token.Valid {
			clearSessionCookie(w)
			http.Redirect(w, r, loginRedirectTarget(r), http.StatusFound)
			return
		}

		if claims, ok := token.Claims.(*sessionClaims); ok {
			if valid, adminFlag := validateSessionClaims(claims); valid {
				ctx := withUsername(r.Context(), claims.Username)
				ctx = withUUID(ctx, claims.UUID)
				ctx = withAdmin(ctx, adminFlag)
				r = r.WithContext(ctx)
			} else {
				clearSessionCookie(w)
				http.Redirect(w, r, loginRedirectTarget(r), http.StatusFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loginRedirectTarget(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	if r.Method != http.MethodGet || strings.TrimSpace(r.URL.Path) != "/oidc/authorize" {
		return "/"
	}
	next := strings.TrimSpace(r.URL.RequestURI())
	if !strings.HasPrefix(next, "/oidc/authorize") {
		return "/"
	}
	q := url.Values{}
	q.Set("next", next)
	return "/?" + q.Encode()
}

func hasValidSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	token, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	}, jwt.WithValidMethods(allowedJWTAlgs))
	if err != nil || !token.Valid {
		return false
	}
	if claims, ok := token.Claims.(*sessionClaims); ok {
		valid, adminFlag := validateSessionClaims(claims)
		_ = adminFlag // admin flag is not used for validity here
		return valid
	}
	return false
}

// ---------- CSRF-lite for state-changing routes ----------
func requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		allowed, allowedHosts, reqOrigin := buildOriginAllowlist(r)
		origin := r.Header.Get("Origin")
		referer := r.Header.Get("Referer")

		if matchesAllowedHeader(origin, allowed, allowedHosts) || matchesAllowedHeader(referer, allowed, allowedHosts) {
			next.ServeHTTP(w, r)
			return
		}

		if origin == "" && referer == "" && requestOriginAllowed(reqOrigin, allowed, allowedHosts) {
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "CSRF check failed", http.StatusForbidden)
	})
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func buildOriginAllowlist(r *http.Request) (map[string]struct{}, map[string]struct{}, string) {
	allowed := make(map[string]struct{}, 4)
	allowedHosts := make(map[string]struct{}, 4)

	if u, err := url.Parse(appBaseURL); err == nil && u.Scheme != "" && u.Host != "" {
		addOriginAllowlist(allowed, allowedHosts, u.Scheme, u.Host)
	}

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
	addOriginAllowlist(allowed, allowedHosts, proto, host)

	if rHost := strings.TrimSpace(r.Host); rHost != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		addOriginAllowlist(allowed, allowedHosts, scheme, rHost)
	}

	return allowed, allowedHosts, proto + "://" + strings.ToLower(host)
}

func firstHeaderValue(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func addOriginAllowlist(allowed map[string]struct{}, hosts map[string]struct{}, scheme, host string) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	host = strings.TrimSpace(host)
	if scheme == "" || host == "" {
		return
	}
	lowerHost := strings.ToLower(host)
	allowed[scheme+"://"+lowerHost] = struct{}{}
	addHostAllowlist(hosts, lowerHost)
	if hostOnly, _, err := net.SplitHostPort(lowerHost); err == nil {
		allowed[scheme+"://"+hostOnly] = struct{}{}
		addHostAllowlist(hosts, hostOnly)
		return
	}
	for _, suffix := range []string{":80", ":443"} {
		if strings.HasSuffix(lowerHost, suffix) {
			trimmed := strings.TrimSuffix(lowerHost, suffix)
			allowed[scheme+"://"+trimmed] = struct{}{}
			addHostAllowlist(hosts, trimmed)
		}
	}
}

func addHostAllowlist(hosts map[string]struct{}, host string) {
	if host == "" {
		return
	}
	hosts[host] = struct{}{}
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		hosts[hostOnly] = struct{}{}
	}
}

func matchesAllowedHeader(hdr string, allowed map[string]struct{}, allowedHosts map[string]struct{}) bool {
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

func requestOriginAllowed(reqOrigin string, allowed map[string]struct{}, allowedHosts map[string]struct{}) bool {
	if reqOrigin == "" {
		return false
	}
	if _, ok := allowed[reqOrigin]; ok {
		return true
	}
	u, err := url.Parse(reqOrigin)
	if err != nil || u.Host == "" {
		return false
	}
	hostKey := strings.ToLower(u.Host)
	if hostOnly, _, err := net.SplitHostPort(hostKey); err == nil {
		if _, ok := allowed[u.Scheme+"://"+hostOnly]; ok {
			return true
		}
		if _, ok := allowedHosts[hostOnly]; ok {
			return true
		}
	}
	_, ok := allowedHosts[hostKey]
	return ok
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
