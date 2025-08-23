// auth-portal/providers.go  (drop-in)
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
	"strings"
	"time"
)

type MediaProvider interface {
	Name() string
	StartWeb(w http.ResponseWriter, r *http.Request)
	Forward(w http.ResponseWriter, r *http.Request)
	IsAuthorized(uuid, username string) (bool, error)
}

/************* helpers *************/
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randClientID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("authportal-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

type plexPinResponse struct {
	ID        int    `json:"id"`
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in"`
	Trusted   bool   `json:"trusted"`
}

func plexCreatePin(clientID string) (plexPinResponse, error) {
	form := url.Values{}
	form.Set("strong", "true")

	req, err := http.NewRequest(http.MethodPost, "https://plex.tv/api/v2/pins", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return plexPinResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0.0")
	req.Header.Set("X-Plex-Client-Identifier", clientID)
	req.Header.Set("X-Plex-Device", "Web")
	req.Header.Set("X-Plex-Platform", "Web")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return plexPinResponse{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plexPinResponse{}, fmt.Errorf("plex pins non-2xx: %d %s", resp.StatusCode, string(body))
	}
	var pin plexPinResponse
	if err := json.Unmarshal(body, &pin); err != nil || pin.Code == "" {
		return plexPinResponse{}, fmt.Errorf("invalid plex pin response")
	}
	return pin, nil
}

func plexAuthURL(clientID, code, forward string) string {
	// Include forwardUrl so Plex comes back to /auth/forward on your app.
	return fmt.Sprintf(
		"https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s&context[device][product]=AuthPortal&context[device][version]=1.0.0&context[device][platform]=Web&context[device][device]=Web",
		url.QueryEscape(clientID),
		url.QueryEscape(code),
		url.QueryEscape(forward),
	)
}

/************* Plex provider *************/
type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

// StartWeb: create PIN -> return auth URL (JSON and/or redirect) so the popup goes to Plex.
func (plexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("X-Client-Id")
	if clientID == "" {
		clientID = randClientID()
	}
	forward := strings.TrimRight(appBaseURL, "/") + "/auth/forward"

	pin, err := plexCreatePin(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "plex pin request failed"})
		return
	}
	authURL := plexAuthURL(clientID, pin.Code, forward)

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") || r.URL.Query().Get("redirect") == "1" || r.FormValue("redirect") == "1" {
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	// Be generous with keys to match various UIs.
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"provider":   "plex",
		"url":        authURL,
		"auth_url":   authURL,
		"redirect":   authURL,
		"location":   authURL,
		"forwardUrl": forward,
		"pin_id":     pin.ID,
		"pin_code":   pin.Code,
		"client_id":  clientID,
		"expires_in": pin.ExpiresIn,
	})
}

// Forward: if called *before* Plex (e.g., your UI opened this first), redirect to Plex.
// If called *after* Plex (referer is app.plex.tv), show a tiny page that notifies the opener and closes.
func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	referer := strings.ToLower(r.Header.Get("Referer"))
	if !strings.Contains(referer, "app.plex.tv") {
		// Not coming from Plex yet → kick off auth here so the popup isn't blank.
		clientID := randClientID()
		forward := strings.TrimRight(appBaseURL, "/") + "/auth/forward"
		pin, err := plexCreatePin(clientID)
		if err != nil {
			http.Error(w, "Plex start failed", http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, plexAuthURL(clientID, pin.Code, forward), http.StatusFound)
		return
	}

	// Coming back from Plex → allow inline script on this one page.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
<title>Plex Login Complete</title>
<body style="font-family:system-ui;padding:2rem">
  <h1>Signing you in…</h1>
  <script>
    // Let the opener know the Plex UI finished; your app can now poll the PIN and set a cookie server-side.
    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage({ ok: true, provider: "plex", source: "auth-forward" }, "*");
      }
    } catch (e) {}
    setTimeout(() => { try { window.close(); } catch(e){} }, 800);
  </script>
  <noscript><p>You can close this window.</p></noscript>
</body>`))
}

func (plexProvider) IsAuthorized(uuid, username string) (bool, error) {
	// Your middleware already requires a valid session cookie. Keep this simple for now.
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
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
<title>Emby Login (Stub)</title>
<body style="font-family:system-ui;padding:2rem">
  <h1>AuthPortal — Emby login (stub)</h1>
  <p>Placeholder; implement real Emby flow here.</p>
</body>`))
}

func (embyProvider) IsAuthorized(uuid, username string) (bool, error) {
	return true, nil
}