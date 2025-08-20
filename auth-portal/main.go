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
	db            *sql.DB
	tmpl          *template.Template
	sessionSecret = []byte(envOr("SESSION_SECRET", "dev-insecure-change-me"))
	appBaseURL    = envOr("APP_BASE_URL", "http://localhost:8089") // <— string, used elsewhere
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
	// DB connect
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

	// Templates
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	// Router
	r := mux.NewRouter()

	// Static files (optional)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public pages
	r.HandleFunc("/", loginPageHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/auth/start-web", startAuthWebHandler).Methods("POST")
	r.HandleFunc("/auth/forward", forwardHandler).Methods("GET")


	// Protected portals
	r.Handle("/home", authMiddleware(http.HandlerFunc(homeHandler))).Methods("GET")
	r.Handle("/me", authMiddleware(http.HandlerFunc(meHandler))).Methods("GET")

	log.Println("Starting Plex Auth on :8080")
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https://plex.tv; style-src 'self' 'unsafe-inline'; script-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// ---------- Session (JWT in HTTP-only cookie) ----------

const sessionCookie = "plex_session"

type sessionClaims struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func setSessionCookie(w http.ResponseWriter, uuid, username string) error {
	now := time.Now()
	claims := sessionClaims{
		UUID:     uuid,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-portal-go",
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
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
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	// mark secure if we’re behind HTTPS
	if strings.HasPrefix(appBaseURL, "https://") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
	return nil
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
