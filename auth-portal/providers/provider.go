package providers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
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

// --- v2 return-value API (non-breaking via adapter) ---

// HTTPResult represents a provider-produced HTTP response
// that the application can write to the client.
type HTTPResult struct {
	Status int
	Header http.Header
	Body   []byte
}

// MediaProviderV2 is the new, return-value oriented interface.
// Existing providers are adapted via v2Adapter below.
type MediaProviderV2 interface {
	Name() string
	Start(ctx context.Context, r *http.Request) (HTTPResult, error)
	Complete(ctx context.Context, r *http.Request) (HTTPResult, error)
	IsAuthorized(uuid, username string) (bool, error)
	Health() error
}

// WriteHTTPResult copies an HTTPResult to the ResponseWriter.
func WriteHTTPResult(w http.ResponseWriter, res HTTPResult) {
	if res.Header != nil {
		for k, vv := range res.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	if res.Status <= 0 {
		res.Status = http.StatusOK
	}
	w.WriteHeader(res.Status)
	if len(res.Body) > 0 {
		_, _ = w.Write(res.Body)
	}
}

// v2Adapter wraps a legacy MediaProvider and captures output.
type v2Adapter struct{ legacy MediaProvider }

// AdaptV2 returns a v2 view over a legacy provider.
func AdaptV2(p MediaProvider) MediaProviderV2 { return v2Adapter{legacy: p} }

func (a v2Adapter) Name() string { return a.legacy.Name() }

func (a v2Adapter) Start(_ context.Context, r *http.Request) (HTTPResult, error) {
	rec := httptest.NewRecorder()
	a.legacy.StartWeb(rec, r)
	return HTTPResult{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}, nil
}

func (a v2Adapter) Complete(_ context.Context, r *http.Request) (HTTPResult, error) {
	rec := httptest.NewRecorder()
	a.legacy.Forward(rec, r)
	return HTTPResult{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}, nil
}

func (a v2Adapter) IsAuthorized(uuid, username string) (bool, error) {
	return a.legacy.IsAuthorized(uuid, username)
}

// Health returns nil by default; concrete providers may implement better checks.
func (a v2Adapter) Health() error {
	if h, ok := any(a.legacy).(interface{ Health() error }); ok {
		return h.Health()
	}
	return nil
}

// --- Structured auth outcome (optional) ---

// AuthOutcome is a provider-agnostic result of a successful authentication
// attempt. Handlers can upsert users and set cookies using these values.
type AuthOutcome struct {
	Provider    string
	Username    string
	Email       string
	MediaUUID   string
	SealedToken string
	Authorized  bool
}

// OutcomeProvider is an optional interface. If implemented by a provider,
// the application will prefer this over raw HTTP handling for /auth/forward.
//
// It may return either an inline HTTP response (for GET forms or waiting pages)
// or a populated AuthOutcome for successful POST completion.
type OutcomeProvider interface {
	CompleteOutcome(ctx context.Context, r *http.Request) (out AuthOutcome, resp *HTTPResult, err error)
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
	Provider    string // plex|emby|jellyfin (for multi-provider identity linking)
}

// Functions and hooks provided by the main application.
var (
	UpsertUser                   func(u User) error
	GetUserByUUID                func(uuid string) (User, error)
	SetUserMediaAccessByUsername func(username string, access bool) error
	FinalizeLogin                func(http.ResponseWriter, string, string) (bool, error)
	SetSessionCookie             func(http.ResponseWriter, string, string) error
	SetTempSessionCookie         func(http.ResponseWriter, string, string) error
	SealToken                    func(string) (string, error)
	Debugf                       func(format string, v ...any)
	Warnf                        func(format string, v ...any)
)

func finalizeAuthorizedLogin(w http.ResponseWriter, mediaUUID, username string) (bool, error) {
	if FinalizeLogin != nil {
		return FinalizeLogin(w, mediaUUID, username)
	}
	if SetSessionCookie != nil {
		if err := SetSessionCookie(w, mediaUUID, username); err != nil {
			return false, err
		}
	}
	return false, nil
}

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

// ProviderDeps holds configuration and hooks injected from main.
type ProviderDeps struct {
	// Config
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

	// Hooks
	UpsertUser                   func(u User) error
	GetUserByUUID                func(uuid string) (User, error)
	SetUserMediaAccessByUsername func(username string, access bool) error
	FinalizeLogin                func(http.ResponseWriter, string, string) (bool, error)
	SetSessionCookie             func(http.ResponseWriter, string, string) error
	SetTempSessionCookie         func(http.ResponseWriter, string, string) error
	SealToken                    func(string) (string, error)
	Debugf                       func(format string, v ...any)
	Warnf                        func(format string, v ...any)
}

// Init wires configuration and hooks into the package-level variables used by legacy providers.
// This provides light-weight DI without rewriting all provider implementations.
func Init(d ProviderDeps) {
	PlexOwnerToken = d.PlexOwnerToken
	PlexServerMachineID = d.PlexServerMachineID
	PlexServerName = d.PlexServerName

	EmbyServerURL = d.EmbyServerURL
	EmbyAppName = d.EmbyAppName
	EmbyAppVersion = d.EmbyAppVersion
	EmbyAPIKey = d.EmbyAPIKey
	EmbyOwnerUsername = d.EmbyOwnerUsername
	EmbyOwnerID = d.EmbyOwnerID

	JellyfinServerURL = d.JellyfinServerURL
	JellyfinAppName = d.JellyfinAppName
	JellyfinAppVersion = d.JellyfinAppVersion
	JellyfinAPIKey = d.JellyfinAPIKey

	UpsertUser = d.UpsertUser
	GetUserByUUID = d.GetUserByUUID
	SetUserMediaAccessByUsername = d.SetUserMediaAccessByUsername
	FinalizeLogin = d.FinalizeLogin
	SetSessionCookie = d.SetSessionCookie
	SetTempSessionCookie = d.SetTempSessionCookie
	SealToken = d.SealToken
	Debugf = d.Debugf
	Warnf = d.Warnf
}
