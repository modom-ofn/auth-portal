package main

import (
	"context"
	"database/sql"
	"errors"
	"html/template"
	"log"
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
	"auth-portal/health"
)

var (
	db                  *sql.DB
	tmpl                *template.Template
	sessionSecret       = []byte(envOr("SESSION_SECRET", "dev-insecure-change-me"))
	appBaseURL          = envOr("APP_BASE_URL", "http://localhost:8089")
	plexOwnerToken      = envOr("PLEX_OWNER_TOKEN", "")
	plexServerMachineID = envOr("PLEX_SERVER_MACHINE_ID", "")
	plexServerName      = envOr("PLEX_SERVER_NAME", "")

	// Optional extra link on the login page
	loginExtraLinkURL  = envOr("LOGIN_EXTRA_LINK_URL", "/some-internal-app")
	loginExtraLinkText = envOr("LOGIN_EXTRA_LINK_TEXT", "Open Internal App")

	// Unauthorized-page "Request Access" mailto link (optional)
	unauthRequestEmail   = envOr("UNAUTH_REQUEST_EMAIL", "admin@example.com")
	unauthRequestSubject = envOr("UNAUTH_REQUEST_SUBJECT", "Request Access")

	// Provider selected at startup (plex default; emby and jellyfin are distinct)
	currentProvider MediaProvider

	// Session TTLs & flags
	sessionTTL        = parseDurationOr(os.Getenv("SESSION_TTL"), 24*time.Hour) // authorized sessions
	forceSecureCookie = os.Getenv("FORCE_SECURE_COOKIE") == "1"                 // force 'Secure' even if APP_BASE_URL is http
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Pick the auth provider (plex default). MEDIA_SERVER: plex | emby | jellyfin
func pickProvider() MediaProvider {
	switch strings.ToLower(os.Getenv("MEDIA_SERVER")) {
	case "jellyfin":
		// Separate provider implementation (no Emby reuse)
		return jellyfinProvider{}
	case "emby":
		return embyProvider{}
	case "plex", "":
		return plexProvider{}
	default:
		log.Printf("Unknown MEDIA_SERVER %q; defaulting to plex", os.Getenv("MEDIA_SERVER"))
		return plexProvider{}
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

	// ---- Templates ----
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	// ---- Provider ----
	currentProvider = pickProvider()
	log.Printf("AuthPortal using provider: %s", currentProvider.Name())

	// ---- Router ----
	r := mux.NewRouter()

	// Static assets
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public
	r.HandleFunc("/", loginPageHandler).Methods("GET")

	// Provider routes
	// Plex uses popup flow (StartWeb + Forward).
	r.HandleFunc("/auth/start-web", currentProvider.StartWeb).Methods("POST", "GET")
	// Emby and Jellyfin use GET (show form/page) and POST (submit credentials) on /auth/forward,
	// implemented by their own provider.Forward.
	r.HandleFunc("/auth/forward", currentProvider.Forward).Methods("GET", "POST")

	// Logout (protect with a simple same-origin check)
	r.Handle("/logout", requireSameOrigin(http.HandlerFunc(logoutHandler))).Methods("POST")

	// Protected
	r.Handle("/home", authMiddleware(http.HandlerFunc(homeHandler))).Methods("GET")
	r.Handle("/me", authMiddleware(http.HandlerFunc(meHandler))).Methods("GET")

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
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Global CSP (the /auth/forward response can set its own relaxed CSP for inline JS)
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: https://plex.tv; style-src 'self' 'unsafe-inline'; script-src 'self'")

		// HSTS only if base URL is HTTPS or you know you're behind TLS
		if strings.HasPrefix(strings.ToLower(appBaseURL), "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=86400; includeSubDomains; preload")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Session (JWT in HTTP-only cookie) ----------

const sessionCookie = "authportal_session"

type sessionClaims struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func setSessionCookieWithTTL(w http.ResponseWriter, uuid, username string, ttl time.Duration) error {
	now := time.Now()
	claims := sessionClaims{
		UUID:     uuid,
		Username: username,
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

	secure := forceSecureCookie || strings.HasPrefix(strings.ToLower(appBaseURL), "https://")

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    signed,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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

func clearSessionCookie(w http.ResponseWriter) {
	// FIX: pass the ResponseWriter as the first argument
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
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
			r = r.WithContext(withUsername(r.Context(), claims.Username))
			r = r.WithContext(withUUID(r.Context(), claims.UUID))
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

		// Build allowed origins set.
		allowed := make(map[string]struct{}, 2)

		// (1) APP_BASE_URL origin
		if u, err := url.Parse(appBaseURL); err == nil && u.Scheme != "" && u.Host != "" {
			allowed[strings.ToLower(u.Scheme+"://"+u.Host)] = struct{}{}
		}

		// (2) origin derived from request / proxy headers
		proto := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")
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
		reqOrigin := strings.ToLower(proto + "://" + host)
		allowed[reqOrigin] = struct{}{}

		// Helper to compare only scheme://host[:port]
		matchesAllowed := func(hdr string) bool {
			if hdr == "" {
				return false
			}
			u, err := url.Parse(hdr)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return false
			}
			got := strings.ToLower(u.Scheme + "://" + u.Host)
			_, ok := allowed[got]
			return ok
		}

		origin := r.Header.Get("Origin")
		referer := r.Header.Get("Referer")

		// Accept if either header matches an allowed origin…
		if matchesAllowed(origin) || matchesAllowed(referer) {
			next.ServeHTTP(w, r)
			return
		}
		// …or if headers are missing but the request origin itself is allowed.
		if origin == "" && referer == "" {
			if _, ok := allowed[reqOrigin]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		http.Error(w, "CSRF check failed", http.StatusForbidden)
	})
}

func parseDurationOr(s string, d time.Duration) time.Duration {
	if v, err := time.ParseDuration(s); err == nil {
		return v
	}
	return d
}