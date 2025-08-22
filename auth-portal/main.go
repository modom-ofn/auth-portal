package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var (
	db                   *sql.DB
	tmpl                 *template.Template
	sessionSecret        = []byte(envOr("SESSION_SECRET", "dev-insecure-change-me"))
	appBaseURL           = envOr("APP_BASE_URL", "http://localhost:8089")
	plexOwnerToken       = envOr("PLEX_OWNER_TOKEN", "")
	plexServerMachineID  = envOr("PLEX_SERVER_MACHINE_ID", "")
	plexServerName       = envOr("PLEX_SERVER_NAME", "")
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
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

	// ---- Router ----
	r := mux.NewRouter()

	// Static assets
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public
	r.HandleFunc("/", loginPageHandler).Methods("GET")
	r.HandleFunc("/auth/start-web", startAuthWebHandler).Methods("POST")
	r.HandleFunc("/auth/forward", forwardHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	// Protected
	r.Handle("/home", authMiddleware(http.HandlerFunc(homeHandler))).Methods("GET")
	r.Handle("/me", authMiddleware(http.HandlerFunc(meHandler))).Methods("GET")

	// Health (optional)
	r.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}).Methods("GET")

	log.Println("Starting AuthPortal on :8080")
	if err := http.ListenAndServe(":8080", withSecurityHeaders(r)); err != nil {
		log.Fatal(err)
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic hardening
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Allow our scripts & inline CSP for /auth/forward response only (that handler sets its own CSP)
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: https://plex.tv; style-src 'self' 'unsafe-inline'; script-src 'self'")

		// HSTS only if we’re serving behind HTTPS
		if strings.HasPrefix(strings.ToLower(appBaseURL), "https://") {
			// one day; tune as needed (e.g., 6 months) when you’re confident
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

	cookie := &http.Cookie{
		Name:     sessionCookie,
		Value:    signed,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()), // <--  TTL in seconds
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if strings.HasPrefix(appBaseURL, "https://") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
	return nil
}

// keep a convenience wrapper for "normal" authorized sessions (24h):
var (
    // e.g. "24h" or "15m"
    sessionTTL = parseDurationOr(os.Getenv("SESSION_TTL"), 24*time.Hour)
    // force secure cookie even if APP_BASE_URL isn't https (useful behind TLS proxy)
    forceSecureCookie = os.Getenv("FORCE_SECURE_COOKIE") == "1"
)

func setSessionCookie(w http.ResponseWriter, uuid, username string) error {
    now := time.Now()
    claims := sessionClaims{
        UUID: uuid, Username: username,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer: "auth-portal-go", Subject: uuid,
            ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL)),
            IssuedAt:  jwt.NewNumericDate(now),
        },
    }
    tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := tok.SignedString(sessionSecret)
    if err != nil { return err }

    c := &http.Cookie{
        Name: sessionCookie, Value: signed, Path: "/",
        MaxAge: int(sessionTTL.Seconds()),
        HttpOnly: true, SameSite: http.SameSiteLaxMode,
        Secure: forceSecureCookie || strings.HasPrefix(appBaseURL, "https://") ||
            strings.EqualFold(rpProtoFrom(w), "https"),
    }
    http.SetCookie(w, c)
    return nil
}

func parseDurationOr(s string, d time.Duration) time.Duration {
    if v, err := time.ParseDuration(s); err == nil { return v }
    return d
}
func rpProtoFrom(w http.ResponseWriter) string { return "" } // (stub if you don’t read X-Forwarded-Proto)


// and one for short-lived (unauthorized) sessions (5 minutes):
func setTempSessionCookie(w http.ResponseWriter, uuid, username string) error {
	return setSessionCookieWithTTL(w, uuid, username, 5*time.Minute)
}

func clearSessionCookie(w http.ResponseWriter) {
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

// ---------- CSRF on state-changing routes ----------
func requireSameOrigin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet || r.Method == http.MethodHead { next.ServeHTTP(w,r); return }
        origin := r.Header.Get("Origin")
        referer := r.Header.Get("Referer")
        allowed := strings.HasPrefix(origin, appBaseURL) || strings.HasPrefix(referer, appBaseURL)
        if !allowed {
            http.Error(w, "CSRF check failed", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}