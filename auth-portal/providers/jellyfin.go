package providers

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Jellyfin uses the same MediaBrowser header schema; keep separate knobs so we can diverge later.
func jellyfinAuthHeader(clientID string) string {
	return fmt.Sprintf(`MediaBrowser Client="%s", Device="Web", DeviceId="%s", Version="%s"`,
		JellyfinAppName, clientID, JellyfinAppVersion)
}

type jellyfinAuthResp struct {
	AccessToken string `json:"AccessToken"`
	User        struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	} `json:"User"`
}

type jellyfinUserDetail struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Policy struct {
		IsDisabled bool `json:"IsDisabled"`
	} `json:"Policy"`
}

type JellyfinProvider struct{}

func (JellyfinProvider) Name() string { return "jellyfin" }

// StartWeb: open our popup-hosted login page
func (JellyfinProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "jellyfin",
		"authUrl":  "/auth/forward?jellyfin=1",
	})
}

func (JellyfinProvider) Forward(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Jellyfin Login</title></head><body style="font-family:system-ui;padding:2rem">
              <h1 style="margin-bottom:1rem"><img src="/static/jellyfin.svg" alt="Jellyfin" width="24" height="24" /> Sign in to Jellyfin</h1>
              <form method="post" action="/auth/forward?jellyfin=1" class="card" style="padding:1rem">
                <label>Username<br><input name="username" autocomplete="username" required></label><br><br>
                <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br><br>
                <button type="submit">Sign In</button>
                <p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(JellyfinServerURL) + `</p>
              </form></body></html>`))
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		http.Redirect(w, r, "/auth/forward?jellyfin=1", http.StatusSeeOther)
		return
	}

	clientID := randClientID()
	auth, err := jellyfinAuthenticate(JellyfinServerURL, clientID, username, password)
	if err != nil {
		if Warnf != nil {
			Warnf("jellyfin/auth Pw failed: %v", err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><head><title>Jellyfin Login Failed</title></head><body style="font-family:system-ui;padding:2rem">
                      <h1 style="margin-bottom:1rem"><img src="/static/jellyfin.svg" alt="Jellyfin" width="24" height="24" /> Sign in to Jellyfin</h1>
                      <form method="post" action="/auth/forward?jellyfin=1">
                        <p style="color:red">Login failed; please try again.</p>
                        <label>Username<br><input name="username" value="` + html.EscapeString(username) + `" autocomplete="username" required></label><br><br>
                        <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br><br>
                        <button type="submit">Sign In</button>
                        <a href="/auth/forward?jellyfin=1" class="muted">Reset</a>
                        <p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(JellyfinServerURL) + `</p>
                      </form></body></html>`))
		return
	}

	if Debugf != nil {
		Debugf("jellyfin/auth success userID=%s", auth.User.ID)
	}
	if ok, terr := jellyfinTokenStillValid(JellyfinServerURL, auth.AccessToken); terr == nil && ok {
		if Debugf != nil {
			Debugf("jellyfin/auth token valid for %s", username)
		}
	}

	var detail jellyfinUserDetail
	if JellyfinAPIKey != "" {
		d, derr := jellyfinGetUserDetail(JellyfinServerURL, JellyfinAPIKey, auth.User.ID)
		if derr == nil {
			detail = d
		} else if Warnf != nil {
			Warnf("jellyfin owner check failed for %s: %v", username, derr)
		}
	}

	authorized := false
	if JellyfinAPIKey != "" && detail.ID != "" && !detail.Policy.IsDisabled {
		authorized = true
	}

	sealedToken, serr := SealToken(auth.AccessToken)
	if serr != nil {
		log.Printf("WARN: jellyfin token seal failed: %v", serr)
		sealedToken = ""
	}
	mediaUUID := "jellyfin-" + auth.User.ID

	if UpsertUser != nil {
		_ = UpsertUser(User{
			Username:    auth.User.Name,
			Email:       "",
			MediaUUID:   mediaUUID,
			MediaToken:  sealedToken,
			MediaAccess: authorized,
		})
	}

	if authorized {
		if SetSessionCookie != nil {
			_ = SetSessionCookie(w, mediaUUID, auth.User.Name)
		}
	} else {
		if SetTempSessionCookie != nil {
			_ = SetTempSessionCookie(w, mediaUUID, auth.User.Name)
		}
	}

	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<html><head><title>Signed in — AuthPortal</title></head><body style="font-family:system-ui;padding:2rem">
              <h1>Signed in — you can close this window.</h1>
              <script>try{if(window.opener&&!window.opener.closed){window.opener.postMessage({ ok: true, type: "jellyfin-auth", redirect: "/home" }, window.location.origin);}}catch(e){};setTimeout(()=>{try{window.close()}catch(e){}},600);</script>
            </body></html>`))
}

func (JellyfinProvider) IsAuthorized(uuid, _username string) (bool, error) {
	if GetUserByUUID == nil {
		return false, fmt.Errorf("GetUserByUUID not configured")
	}
	u, err := GetUserByUUID(uuid)
	if err != nil {
		return false, err
	}
	if u.MediaAccess {
		return true, nil
	}
	if JellyfinAPIKey != "" && u.MediaUUID != "" {
		id := strings.TrimPrefix(u.MediaUUID, "jellyfin-")
		if detail, derr := jellyfinGetUserDetail(JellyfinServerURL, JellyfinAPIKey, id); derr == nil {
			ok := !detail.Policy.IsDisabled
			if SetUserMediaAccessByUsername != nil {
				_ = SetUserMediaAccessByUsername(u.Username, ok)
			}
			return ok, nil
		}
	}
	return false, nil
}

func jellyfinAuthenticate(serverURL, clientID, username, password string) (jellyfinAuthResp, error) {
	base := strings.TrimSuffix(serverURL, "/")
	if Debugf != nil {
		Debugf("jellyfin/auth start server=%s user=%q", base, username)
	}
	out, err := jellyfinAuthAttempt(base, clientID, map[string]string{
		"Username": username,
		"Password": password,
	})
	if err == nil {
		if Debugf != nil {
			Debugf("jellyfin/auth success (Pw) userID=%s", out.User.ID)
		}
		return out, nil
	}
	if Warnf != nil {
		Warnf("jellyfin/auth Pw failed: %v", err)
	}
	out2, err2 := jellyfinAuthAttempt(base, clientID, map[string]string{
		"pw":       password,
		"username": username,
	})
	if err2 == nil {
		if Debugf != nil {
			Debugf("jellyfin/auth success (Password) userID=%s", out2.User.ID)
		}
		return out2, nil
	}
	return jellyfinAuthResp{}, err2
}

func jellyfinAuthAttempt(baseURL, clientID string, body map[string]string) (jellyfinAuthResp, error) {
	loginURL := baseURL + "/Users/AuthenticateByName"
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", jellyfinAuthHeader(clientID))
	req.Header.Set("X-Emby-Client", JellyfinAppName)
	req.Header.Set("X-Emby-Client-Version", JellyfinAppVersion)
	if Debugf != nil {
		Debugf("jellyfin/auth POST %s", loginURL)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return jellyfinAuthResp{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		snippet := string(raw)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		if Warnf != nil {
			Warnf("jellyfin/auth HTTP %d body=%q", resp.StatusCode, snippet)
		}
		return jellyfinAuthResp{}, fmt.Errorf("jellyfin auth %d: %s", resp.StatusCode, snippet)
	}
	var out jellyfinAuthResp
	if err := json.Unmarshal(raw, &out); err != nil {
		if Warnf != nil {
			Warnf("jellyfin/auth decode failed: %v body=%q", err, string(raw))
		}
		return jellyfinAuthResp{}, fmt.Errorf("jellyfin auth decode failed: %w", err)
	}
	return out, nil
}

func jellyfinGetUserDetail(serverURL, apiKey, userID string) (jellyfinUserDetail, error) {
	u := strings.TrimSuffix(serverURL, "/") + "/Users/" + userID
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf(`MediaBrowser Token="%s"`, apiKey))
		req.Header.Set("X-MediaBrowser-Token", apiKey)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return jellyfinUserDetail{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return jellyfinUserDetail{}, fmt.Errorf("jellyfin user %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out jellyfinUserDetail
	if err := json.Unmarshal(raw, &out); err != nil {
		return jellyfinUserDetail{}, fmt.Errorf("jellyfin user decode failed: %w", err)
	}
	return out, nil
}

func jellyfinTokenStillValid(serverURL, token string) (bool, error) {
	req, _ := http.NewRequest(http.MethodGet, serverURL+"/users/Me", nil)
	req.Header.Set("X-Emby-Token", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == 200, nil
}
