package providers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// MediaProvider defines the behavior required for media providers.
type MediaProvider interface {
	Name() string
	StartWeb(w http.ResponseWriter, r *http.Request)
	Forward(w http.ResponseWriter, r *http.Request)
	IsAuthorized(uuid, username string) (bool, error)
}

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// randClientID creates a random 16-byte hex string for client identifiers.
func randClientID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "authportal-" + time.Now().Format("150405")
	}
	return hex.EncodeToString(b[:])
}

// htmlEscape returns HTML-escaped string.
func htmlEscape(s string) string {
	var b strings.Builder
	template.HTMLEscape(&b, []byte(s))
	return b.String()
}

// User represents minimal user fields needed by providers.
type User struct {
	Username    string
	Email       string
	MediaUUID   string
	MediaToken  string
	MediaAccess bool
}

// Functions and hooks provided by the main application.
var (
	UpsertUser                   func(u User) error
	GetUserByUUID                func(uuid string) (User, error)
	SetUserMediaAccessByUsername func(username string, access bool) error
	SetSessionCookie             func(http.ResponseWriter, string, string) error
	SetTempSessionCookie         func(http.ResponseWriter, string, string) error
	SealToken                    func(string) (string, error)
	Debugf                       func(format string, v ...any)
	Warnf                        func(format string, v ...any)
)

// Configuration values for the providers; populated by main.
var (
	PlexOwnerToken      string
	PlexServerMachineID string
	PlexServerName      string

	EmbyServerURL     string
	EmbyAppName       string
	EmbyAppVersion    string
	EmbyAPIKey        string
	EmbyOwnerUsername string
	EmbyOwnerID       string

	JellyfinServerURL  string
	JellyfinAppName    string
	JellyfinAppVersion string
	JellyfinAPIKey     string
)
