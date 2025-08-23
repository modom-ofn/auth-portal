package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

/************* Provider interface *************/

type MediaProvider interface {
	Name() string
	StartWeb(w http.ResponseWriter, r *http.Request)
	Forward(w http.ResponseWriter, r *http.Request)
	IsAuthorized(uuid, username string) (bool, error)
}

/************* Shared helpers *************/

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randClientID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// fallback to timestamp-based if crypto/rand fails (very unlikely)
		return fmt.Sprintf("authportal-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

/************* Plex *************/

type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

type plexPinResponse struct {
	ID        int    `json:"id"`
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in"`
	CreatedAt string `json:"created_at"`
	Trusted   bool   `json:"trusted"`
}

// StartWeb starts a real Plex PIN auth by creating a PIN, then returning the
// official Plex auth URL the frontend should open.
func (plexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("X-Client-Id")
	if clientID == "" {
		clientID = randClientID()
	}

	// Create a PIN at plex.tv
	form := url.Values{}
	form.Set("strong", "true")

	req, err := http.NewRequest(http.MethodPost, "https://plex.tv/api/v2/pins", bytes.NewBufferString(form.Encode()))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "request build failed"})
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Standard X-Plex headers (product/version/name are arbitrary but nice to set)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0.0")
	req.Header.Set("X-Plex-Client-Identifier", clientID)
	req.Header.Set("X-Plex-Device", "Web")
	req.Header.Set("X-Plex-Platform", "Web")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "plex pin request failed"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "plex pin non-2xx", "status": resp.StatusCode, "body": string(body)})
		return
	}

	var pin plexPinResponse
	if err := json.Unmarshal(body, &pin); err != nil || pin.Code == "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "invalid plex pin response"})
		return
	}

	// Construct the official Plex login URL. This opens the Plex login/approval UI.
	// See: Plex “PIN” flow — requires code + clientID in the fragment.
	authURL := fmt.Sprintf(
		"https://app.plex.tv/auth#?code=%s&clientID=%s&context[device][product]=AuthPortal&context[device][version]=1.0.0&context[device][platform]=Web&context[device][device]=Web",
		url.QueryEscape(pin.Code),
		url.QueryEscape(clientID),
	)

	// Frontend should open 'url' in a popup or navigate there.
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"provider":   "plex",
		"url":        authURL,
		"pin_id":     pin.ID,
		"pin_code":   pin.Code,
		"client_id":  clientID,
		"expires_in": pin.ExpiresIn,
	})
}

// Forward is left as a simple placeholder so your flow doesn’t error.
// Later: have your client call a server endpoint that polls
// GET https://plex.tv/api/v2/pins/{id} with the same headers until token appears,
// then set the session cookie server-side and redirect to /home.
func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`
<!doctype html><meta charset="utf-8">
<title>Plex Login (Waiting)</title>
<body style="font-family:system-ui;padding:2rem">
  <h1>AuthPortal — Waiting for Plex approval…</h1>
  <p>Finish login in the Plex window. This page will close shortly.</p>
  <script>
    setTimeout(() => { try { window.close(); } catch(e){} }, 1500);
  </script>
</body>
`))
}

func (plexProvider) IsAuthorized(uuid, username string) (bool, error) {
	// TODO: implement a real provider-specific authorization check if needed.
	// For now, your authMiddleware enforces a valid session cookie already.
	return true, nil
}

/************* Emby (still stubbed) *************/

type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }

func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "emby",
		"url":      "/auth/forward",
		"message":  "Emby login stub; replace with real flow.",
	})
}

func (embyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`
<!doctype html><meta charset="utf-8">
<title>Emby Login (Stub)</title>
<body style="font-family:system-ui;padding:2rem">
  <h1>AuthPortal — Emby login (stub)</h1>
  <p>Placeholder; implement real Emby flow here.</p>
</body>
`))
}

func (embyProvider) IsAuthorized(uuid, username string) (bool, error) {
	return true, nil
}