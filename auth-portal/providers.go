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

/************* Provider interface *************/
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

type plexPin struct {
	ID        int    `json:"id"`
	Code      string `json:"code"`
	AuthToken string `json:"authToken"` // sometimes present on GET after approval
	// Some responses use snake_case; we’ll decode both
	AuthToken2 string `json:"auth_token"`
	// Other fields omitted
}

func plexCreatePin(clientID string) (plexPin, error) {
	form := url.Values{}
	form.Set("strong", "true")

	req, err := http.NewRequest(http.MethodPost, "https://plex.tv/api/v2/pins", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return plexPin{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0.0")
	req.Header.Set("X-Plex-Client-Identifier", clientID)
	req.Header.Set("X-Plex-Device", "Web")
	req.Header.Set("X-Plex-Platform", "Web")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return plexPin{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plexPin{}, fmt.Errorf("plex pins non-2xx: %d %s", resp.StatusCode, string(body))
	}
	var pin plexPin
	if err := json.Unmarshal(body, &pin); err != nil || pin.Code == "" {
		return plexPin{}, fmt.Errorf("invalid plex pin response")
	}
	return pin, nil
}

func plexPollPin(clientID string, id int, timeout time.Duration) (token string, err error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://plex.tv/api/v2/pins/%d", id), nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Plex-Product", "AuthPortal")
		req.Header.Set("X-Plex-Version", "1.0.0")
		req.Header.Set("X-Plex-Client-Identifier", clientID)
		req.Header.Set("X-Plex-Device", "Web")
		req.Header.Set("X-Plex-Platform", "Web")

		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err == nil && resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var p plexPin
				if json.Unmarshal(body, &p) == nil {
					if p.AuthToken != "" {
						return p.AuthToken, nil
					}
					if p.AuthToken2 != "" {
						return p.AuthToken2, nil
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("timeout waiting for plex pin")
}

type plexUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func plexFetchUser(token string) (plexUser, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://plex.tv/api/v2/user", nil)
	req.Header.Set("Accept", "application/json")
	// Plex accepts token via header:
	req.Header.Set("X-Plex-Token", token)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0.0")
	req.Header.Set("X-Plex-Client-Identifier", "authportal-userinfo")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return plexUser{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plexUser{}, fmt.Errorf("plex user non-2xx: %d %s", resp.StatusCode, string(b))
	}
	var u plexUser
	if err := json.Unmarshal(b, &u); err != nil {
		// Some Plex endpoints are XML; fall back to a generic user
		return plexUser{ID: 0, Username: "plex-user"}, nil
	}
	return u, nil
}

/************* Plex provider *************/
type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

// StartWeb: create PIN and return the official auth URL as { authUrl: ... }
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
	authURL := fmt.Sprintf(
		"https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s&context[device][product]=AuthPortal&context[device][version]=1.0.0&context[device][platform]=Web&context[device][device]=Web",
		url.QueryEscape(clientID), url.QueryEscape(pin.Code), url.QueryEscape(forward),
	)

	// Stash pin+client in a short-lived, HTTP-only cookie so /auth/forward can finish the flow.
	http.SetCookie(w, &http.Cookie{
		Name:     "plex_pin",
		Value:    fmt.Sprintf("%d:%s", pin.ID, clientID),
		Path:     "/",
		MaxAge:   180, // 3 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// dev-r2 frontend reads "authUrl"
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"provider":   "plex",
		"authUrl":    authURL,
		"pin_id":     pin.ID,
		"client_id":  clientID,
		"expires_in": 120,
	})
}

// Forward: complete the login, set cookie, and notify/close the popup.
func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	// If we arrive here first (no cookie), bootstrap by starting the flow.
	pc, _ := r.Cookie("plex_pin")
	if pc == nil || pc.Value == "" {
		// Create a PIN and bounce to Plex so the popup isn't blank.
		clientID := randClientID()
		forward := strings.TrimRight(appBaseURL, "/") + "/auth/forward"
		pin, err := plexCreatePin(clientID)
		if err != nil {
			http.Error(w, "Plex start failed", http.StatusBadGateway)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "plex_pin",
			Value:    fmt.Sprintf("%d:%s", pin.ID, clientID),
			Path:     "/",
			MaxAge:   180,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, fmt.Sprintf(
			"https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s",
			url.QueryEscape(clientID), url.QueryEscape(pin.Code), url.QueryEscape(forward),
		), http.StatusFound)
		return
	}

	// Parse cookie "pinID:clientID"
	parts := strings.SplitN(pc.Value, ":", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid plex pin cookie", http.StatusBadRequest)
		return
	}
	pinIDStr, clientID := parts[0], parts[1]
	var pinID int
	fmt.Sscanf(pinIDStr, "%d", &pinID)

	// Poll Plex for auth token (up to ~60s)
	token, err := plexPollPin(clientID, pinID, 60*time.Second)
	if err != nil {
		// Keep the popup informative instead of blank.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
<title>Plex: Waiting for approval…</title>
<body style="font-family:system-ui;padding:2rem">
  <h1>Waiting for Plex approval…</h1>
  <p>If you already approved, please close this window and click Sign in again.</p>
</body>`))
		return
	}

	// Fetch basic user info (best-effort)
	user, _ := plexFetchUser(token)
	uuid := fmt.Sprintf("plex-%d", user.ID)
	if uuid == "plex-0" {
		uuid = "plex-user"
	}
	username := user.Username
	if username == "" {
		username = "plex-user"
	}

	// TODO: persist token securely (e.g., encrypted in DB). For now, complete session.
	_ = setSessionCookie(w, uuid, username)

	// Finalize the popup → relax CSP so inline script can postMessage + close.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// We always send opener to /home; your server decides authorized vs unauthorized.
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
<title>Signed in — AuthPortal</title>
<body style="font-family:system-ui;padding:2rem">
  <h1>Signed in — you can close this window.</h1>
  <script>
    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage({ ok: true, type: "plex-auth", redirect: "/home" }, window.location.origin);
      }
    } catch (e) {}
    setTimeout(() => { try { window.close(); } catch(e){} }, 600);
  </script>
  <noscript><p>Close this window and return to the app.</p></noscript>
</body>`))
}

// Keep IsAuthorized simple for now; your /home handler determines page.
func (plexProvider) IsAuthorized(_uuid, _username string) (bool, error) {
	// If you want to gate by Plex server membership, add the check here later.
	return true, nil
}

/************* Emby (still stubbed) *************/
type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }
func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "emby",
		"authUrl":  "/auth/forward",
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
func (embyProvider) IsAuthorized(_uuid, _username string) (bool, error) { return true, nil }