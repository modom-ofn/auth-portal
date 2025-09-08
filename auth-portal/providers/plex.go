package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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

// GET JSON with standard Plex headers
func plexGetJSON(u, token string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Token", token)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "2.0.0")
	req.Header.Set("X-Plex-Client-Identifier", "auth-portal")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s := strings.TrimSpace(string(body))
		if len(s) > 200 {
			s = s[:200] + "…"
		}
		return fmt.Errorf("plex %s -> %d: %s", u, resp.StatusCode, s)
	}
	return json.Unmarshal(body, out)
}

// plexAccountID returns the numeric/string id for the token's account.
func plexAccountID(token string) (string, error) {
	var resp struct {
		ID string `json:"id"`
	}
	if err := plexGetJSON("https://plex.tv/api/v2/user", token, &resp); err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.ID), nil
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
	req.Header.Set("X-Plex-Version", "2.0.0")
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
		req.Header.Set("X-Plex-Version", "2.0.0")
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
	req.Header.Set("X-Plex-Version", "2.0.0")
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

// plexUserHasServer: true if user's token can see configured server in /resources (v2)
func plexUserHasServer(userToken string) (bool, error) {
	if userToken == "" {
		return false, nil
	}
	req, _ := http.NewRequest(http.MethodGet, "https://plex.tv/api/v2/resources?includeHttps=1", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Token", userToken)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "2.0.0")
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
		return false, err
	}
	wantMID := strings.TrimSpace(PlexServerMachineID)
	wantName := strings.TrimSpace(PlexServerName)
	for _, r := range rs {
		if !strings.Contains(r.Provides, "server") {
			continue
		}
		if wantMID != "" && r.ClientIdentifier == wantMID {
			return true, nil
		}
		if wantName != "" && r.Name == wantName {
			return true, nil
		}
	}
	return false, nil
}

type PlexProvider struct{}

func (PlexProvider) Name() string { return "plex" }

// StartWeb: create PIN → return Plex UI URL
func (PlexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	clientID := randClientID()
	pin, err := plexCreatePin(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "plex pin request failed"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "plex_pin",
		Value:    fmt.Sprintf("%d:%s", pin.ID, pin.Code),
		Path:     "/auth/forward",
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
	})
	url := fmt.Sprintf("https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s&context[device][product]=AuthPortal&context[device][version]=2.0.0&context[device][platform]=Web&context[device][device]=Web", clientID, pin.Code, url.QueryEscape(r.URL.Scheme+"://"+r.Host+"/auth/forward"))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "plex",
		"url":      url,
	})
}

func (PlexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	pc, _ := r.Cookie("plex_pin")
	if pc == nil {
		http.Error(w, "missing plex pin cookie", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(pc.Value, ":", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid plex pin cookie", http.StatusBadRequest)
		return
	}
	pinID, _ := strconv.Atoi(parts[0])
	clientID := randClientID()
	token, err := plexPollPin(clientID, pinID, 60*time.Second)
	if err != nil || token == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><title>Plex: Waiting…</title><body style="font-family:system-ui;padding:2rem"><h1>Waiting for Plex approval…</h1></body>`))
		return
	}

	user, _ := plexFetchUser(token)
	username := user.Username
	if username == "" {
		username = "plex-user"
	}
	mediaUUID := fmt.Sprintf("plex-%d", user.ID)
	email := user.Email

	sealedToken, err := SealToken(token)
	if err != nil {
		log.Printf("WARN: token seal failed: %v (storing empty token)", err)
		sealedToken = ""
	}

	authorized := false
	if strings.TrimSpace(PlexServerMachineID) != "" || strings.TrimSpace(PlexServerName) != "" {
		if ok, _ := plexUserHasServer(token); ok {
			authorized = true
		}
	} else if strings.TrimSpace(PlexOwnerToken) != "" {
		if uid, e1 := plexAccountID(token); e1 == nil {
			if oid, e2 := plexAccountID(PlexOwnerToken); e2 == nil && uid == oid {
				authorized = true
			}
		}
	}

	if UpsertUser != nil {
		_ = UpsertUser(User{
			Username:    username,
			Email:       email,
			MediaUUID:   mediaUUID,
			MediaToken:  sealedToken,
			MediaAccess: authorized,
		})
	}

	if authorized {
		if SetSessionCookie != nil {
			_ = SetSessionCookie(w, mediaUUID, username)
		}
	} else {
		if SetTempSessionCookie != nil {
			_ = SetTempSessionCookie(w, mediaUUID, username)
		}
	}

	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Signed in — AuthPortal</title><body style="font-family:system-ui;padding:2rem"><h1>Signed in — you can close this window.</h1><script>try{if(window.opener&&!window.opener.closed){window.opener.postMessage({ok:true,type:"plex-auth",redirect:"/home"},window.location.origin)}}catch(e){};setTimeout(()=>{try{window.close()}catch(e){}},600);</script></body>`))
}

func (PlexProvider) IsAuthorized(uuid, _username string) (bool, error) {
	if GetUserByUUID == nil {
		return false, errors.New("GetUserByUUID not configured")
	}
	u, err := GetUserByUUID(uuid)
	if err != nil {
		return false, err
	}
	if u.MediaAccess {
		return true, nil
	}
	if strings.TrimSpace(u.MediaToken) == "" {
		return false, nil
	}
	userToken := strings.TrimSpace(u.MediaToken)

	if strings.TrimSpace(PlexServerMachineID) != "" || strings.TrimSpace(PlexServerName) != "" {
		ok, err := plexUserHasServer(userToken)
		if err == nil {
			if ok {
				if SetUserMediaAccessByUsername != nil {
					_ = SetUserMediaAccessByUsername(u.Username, true)
				}
			}
			return ok, nil
		}
		if Debugf != nil {
			Debugf("plex: server visibility check failed: %v", err)
		}
	}

	if strings.TrimSpace(PlexOwnerToken) != "" {
		usrID, e1 := plexAccountID(userToken)
		ownID, e2 := plexAccountID(PlexOwnerToken)
		if e1 == nil && e2 == nil && usrID != "" && usrID == ownID {
			if SetUserMediaAccessByUsername != nil {
				_ = SetUserMediaAccessByUsername(u.Username, true)
			}
			return true, nil
		}
	}

	return false, nil
}
