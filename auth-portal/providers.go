package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

/************* shared helpers *************/
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

/************* Plex API types *************/
type plexPin struct {
	ID         int    `json:"id"`
	Code       string `json:"code"`
	AuthToken  string `json:"authToken"`
	AuthToken2 string `json:"auth_token"`
}

type plexUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type plexResource struct {
	Name             string `json:"name"`
	Provides         string `json:"provides"`
	ClientIdentifier string `json:"clientIdentifier"`
}

/************* Plex helpers *************/
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

func plexFetchUser(token string) (plexUser, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://plex.tv/api/v2/user", nil)
	req.Header.Set("Accept", "application/json")
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
		return plexUser{ID: 0, Username: "plex-user"}, nil
	}
	return u, nil
}

// plexUserHasServer returns true if the *user's* token can see the configured server
// in /api/v2/resources (shared servers are listed there).
func plexUserHasServer(userToken string) (bool, error) {
	if userToken == "" {
		return false, nil
	}
	req, _ := http.NewRequest(http.MethodGet, "https://plex.tv/api/v2/resources?includeHttps=1", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Token", userToken)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0.0")
	req.Header.Set("X-Plex-Client-Identifier", "authportal-check")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("resources non-2xx: %d %s", resp.StatusCode, string(body))
	}

	var rs []plexResource
	if err := json.Unmarshal(body, &rs); err != nil {
		// Some Plex endpoints can return XML; treat as not authorized if we can't parse JSON
		return false, nil
	}

	wantMID := strings.TrimSpace(plexServerMachineID)
	wantName := strings.TrimSpace(plexServerName)
	for _, r := range rs {
		if !strings.Contains(strings.ToLower(r.Provides), "server") {
			continue
		}
		if wantMID != "" && strings.EqualFold(r.ClientIdentifier, wantMID) {
			return true, nil
		}
		if wantMID == "" && wantName != "" && strings.EqualFold(r.Name, wantName) {
			return true, nil
		}
	}
	return false, nil
}

/************* Plex provider *************/
type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

// StartWeb: create PIN and return { authUrl: ... } (popup flow)
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

	// Keep pin & client in a short-lived cookie so Forward can finish
	http.SetCookie(w, &http.Cookie{
		Name:     "plex_pin",
		Value:    fmt.Sprintf("%d:%s", pin.ID, clientID),
		Path:     "/",
		MaxAge:   180,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := fmt.Sprintf(
		"https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s&context[device][product]=AuthPortal&context[device][version]=1.0.0&context[device][platform]=Web&context[device][device]=Web",
		url.QueryEscape(clientID), url.QueryEscape(pin.Code), url.QueryEscape(forward),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"provider":   "plex",
		"authUrl":    authURL,
		"pin_id":     pin.ID,
		"client_id":  clientID,
		"expires_in": 120,
	})
}

// Forward: poll → fetch user → check server access → save → set session → postMessage to close popup.
func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	pc, _ := r.Cookie("plex_pin")
	if pc == nil || pc.Value == "" {
		// Bootstrap if opened directly
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

	parts := strings.SplitN(pc.Value, ":", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid plex pin cookie", http.StatusBadRequest)
		return
	}
	pinIDStr, clientID := parts[0], parts[1]
	var pinID int
	fmt.Sscanf(pinIDStr, "%d", &pinID)

	// 1) Poll for token
	token, err := plexPollPin(clientID, pinID, 60*time.Second)
	if err != nil || token == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Plex: Waiting…</title><body style="font-family:system-ui;padding:2rem"><h1>Waiting for Plex approval…</h1></body>`))
		return
	}

	// 2) Fetch user info
	user, _ := plexFetchUser(token)
	username := user.Username
	if username == "" {
		username = "plex-user"
	}
	plexUUID := fmt.Sprintf("plex-%d", user.ID)
	email := user.Email

	// 3) Seal token for storage
	sealed, err := SealToken(token)
	if err != nil {
		log.Printf("WARN: token seal failed: %v (storing empty token)", err)
	}

	// 4) Check authorization: can *this user* see your server in /resources?
	authorized := false
	if plexServerMachineID != "" || plexServerName != "" {
		if ok, chkErr := plexUserHasServer(token); chkErr == nil {
			authorized = ok
		} else {
			log.Printf("auth check failed for %s: %v", username, chkErr)
		}
	} else {
		// If server not configured, be conservative: treat as unauthorized.
		authorized = false
	}

	// 5) Persist to DB (email + sealed token + access flag)
	_, _ = upsertUser(User{
		Username:   username,
		Email:      nullStringFrom(email),
		PlexUUID:   nullStringFrom(plexUUID),
		PlexToken:  nullStringFrom(sealed),
		PlexAccess: authorized,
	})

	// 6) Issue session and close popup
	if authorized {
		_ = setSessionCookie(w, plexUUID, username)
	} else {
		// short-lived session keeps them "logged in" (so UI can show "unauthorized" page)
		_ = setTempSessionCookie(w, plexUUID, username)
	}

	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	dest := "/home" // your /home handler shows authorized vs unauthorized content
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Signed in — AuthPortal</title><body style="font-family:system-ui;padding:2rem"><h1>Signed in — you can close this window.</h1><script>try{if(window.opener&&!window.opener.closed){window.opener.postMessage({ok:true,type:"plex-auth",redirect:"` + dest + `"},window.location.origin)}}catch(e){};setTimeout(()=>{try{window.close()}catch(e){}},600);</script></body>`))
}

// IsAuthorized: prefer DB flag; if unknown but we have a token, verify once and update DB.
func (plexProvider) IsAuthorized(uuid, _username string) (bool, error) {
	u, err := getUserByUUID(uuid)
	if err != nil {
		return false, err
	}
	// If DB already knows, trust it.
	if u.PlexAccess {
		return true, nil
	}
	// Try an on-demand check if we have a token
	if u.PlexToken.Valid && u.PlexToken.String != "" {
		ok, err := plexUserHasServer(u.PlexToken.String)
		if err == nil {
			_ = setUserPlexAccessByUsername(u.Username, ok) // best-effort
			return ok, nil
		}
	}
	return false, nil
}

/************* Emby (stub) *************/
type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }
func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider": "emby", "authUrl": "/auth/forward"})
}
func (embyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Emby (Stub)</title>`))
}
// Default to false until a real Emby check is implemented.
func (embyProvider) IsAuthorized(_uuid, _username string) (bool, error) { return false, nil }