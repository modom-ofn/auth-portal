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

// Build the MediaBrowser auth header used by Emby
func embyAuthHeader(clientID string) string {
	return fmt.Sprintf(`MediaBrowser Client="%s", Device="Web", DeviceId="%s", Version="%s"`,
		EmbyAppName, clientID, EmbyAppVersion)
}

type embyAuthResp struct {
	AccessToken string `json:"AccessToken"`
	User        struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	} `json:"User"`
}

type embyUserDetail struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Policy struct {
		IsDisabled bool `json:"IsDisabled"`
	} `json:"Policy"`
}

type EmbyProvider struct{}

func (EmbyProvider) Name() string { return "emby" }

// StartWeb: tell the client to open our own login form popup (/auth/forward?emby=1)
func (EmbyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "emby",
		"authUrl":  "/auth/forward?emby=1",
	})
}

func (EmbyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Emby Login</title></head><body style="font-family:system-ui;padding:2rem">
              <h1 style="margin-bottom:1rem"><img src="/static/emby.svg" alt="Emby" width="24" height="24" /> Sign in to Emby</h1>
              <form method="post" action="/auth/forward?emby=1" class="card" style="padding:1rem">
                <label>Username<br><input name="username" autocomplete="username" required></label><br><br>
                <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br><br>
                <button type="submit">Sign In</button>
                <p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(EmbyServerURL) + `</p>
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
		http.Redirect(w, r, "/auth/forward?emby=1", http.StatusSeeOther)
		return
	}

	clientID := randClientID()
	auth, err := embyAuthenticate(EmbyServerURL, clientID, username, password)
	if err != nil {
		if Warnf != nil {
			Warnf("emby/auth Pw failed: %v", err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><head><title>Emby Login Failed</title></head><body style="font-family:system-ui;padding:2rem">
                      <h1 style="margin-bottom:1rem"><img src="/static/emby.svg" alt="Emby" width="24" height="24" /> Sign in to Emby</h1>
                      <form method="post" action="/auth/forward?emby=1">
                        <p style="color:red">Login failed; please try again.</p>
                        <label>Username<br><input name="username" value="` + html.EscapeString(username) + `" autocomplete="username" required></label><br><br>
                        <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br><br>
                        <button type="submit">Sign In</button>
                        <a href="/auth/forward?emby=1" class="muted">Reset</a>
                        <p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(EmbyServerURL) + `</p>
                      </form></body></html>`))
		return
	}

	if Debugf != nil {
		Debugf("emby/auth success userID=%s", auth.User.ID)
	}
	if ok, terr := embyTokenStillValid(EmbyServerURL, auth.AccessToken); terr == nil && ok {
		if Debugf != nil {
			Debugf("emby/auth token valid for %s", username)
		}
	}

	var detail embyUserDetail
	if EmbyAPIKey != "" {
		d, derr := embyGetUserDetail(EmbyServerURL, EmbyAPIKey, auth.User.ID)
		if derr == nil {
			detail = d
		} else if Warnf != nil {
			Warnf("emby detail fetch failed for %s: %v", auth.User.Name, derr)
		}
	}

	authorized := false
	if EmbyOwnerUsername != "" && auth.User.Name == EmbyOwnerUsername {
		authorized = true
	}
	if EmbyOwnerID != "" && auth.User.ID == EmbyOwnerID {
		authorized = true
	}
	if EmbyAPIKey != "" && detail.ID != "" && !detail.Policy.IsDisabled {
		authorized = true
	}

	sealedToken, serr := SealToken(auth.AccessToken)
	if serr != nil {
		log.Printf("WARN: emby token seal failed: %v", serr)
		sealedToken = ""
	}
	mediaUUID := "emby-" + auth.User.ID

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
              <script>try{if(window.opener&&!window.opener.closed){window.opener.postMessage({ ok: true, type: "emby-auth", redirect: "/home" }, window.location.origin);}}catch(e){};setTimeout(()=>{try{window.close()}catch(e){}},600);</script>
            </body></html>`))
}

func (EmbyProvider) IsAuthorized(uuid, _username string) (bool, error) {
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
	if EmbyAPIKey != "" && u.MediaUUID != "" {
		id := strings.TrimPrefix(u.MediaUUID, "emby-")
		if detail, derr := embyGetUserDetail(EmbyServerURL, EmbyAPIKey, id); derr == nil {
			ok := !detail.Policy.IsDisabled
			if SetUserMediaAccessByUsername != nil {
				_ = SetUserMediaAccessByUsername(u.Username, ok)
			}
			return ok, nil
		}
	}
	return false, nil
}

// embyTokenStillValid checks whether the user's token is currently accepted by the server.
func embyTokenStillValid(serverURL, token string) (bool, error) {
	req, _ := http.NewRequest(http.MethodGet, serverURL+"/users/Me", nil)
	req.Header.Set("X-Emby-Token", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == 200, nil
}

func embyAuthenticate(serverURL, clientID, username, password string) (embyAuthResp, error) {
	base := strings.TrimSuffix(serverURL, "/")
	if Debugf != nil {
		Debugf("emby/auth start server=%s user=%q", base, username)
	}
	out, err := embyAuthAttempt(base, clientID, map[string]string{
		"Username": username,
		"Password": password,
	})
	if err == nil {
		if Debugf != nil {
			Debugf("emby/auth success (Pw) userID=%s", out.User.ID)
		}
		return out, nil
	}
	if Warnf != nil {
		Warnf("emby/auth Pw failed: %v", err)
	}
	out2, err2 := embyAuthAttempt(base, clientID, map[string]string{
		"pw":       password,
		"username": username,
	})
	if err2 == nil {
		if Debugf != nil {
			Debugf("emby/auth success (Password) userID=%s", out2.User.ID)
		}
		return out2, nil
	}
	return embyAuthResp{}, err2
}

func embyAuthAttempt(baseURL, clientID string, body map[string]string) (embyAuthResp, error) {
	loginURL := baseURL + "/Users/AuthenticateByName"
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", embyAuthHeader(clientID))
	req.Header.Set("X-Emby-Client", EmbyAppName)
	req.Header.Set("X-Emby-Client-Version", EmbyAppVersion)
	if Debugf != nil {
		Debugf("emby/auth POST %s", loginURL)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return embyAuthResp{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		snippet := string(raw)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		if Warnf != nil {
			Warnf("emby/auth HTTP %d body=%q", resp.StatusCode, snippet)
		}
		return embyAuthResp{}, fmt.Errorf("emby auth %d: %s", resp.StatusCode, snippet)
	}
	var out embyAuthResp
	if err := json.Unmarshal(raw, &out); err != nil {
		if Warnf != nil {
			Warnf("emby/auth decode failed: %v body=%q", err, string(raw))
		}
		return embyAuthResp{}, fmt.Errorf("emby auth decode failed: %w", err)
	}
	return out, nil
}

func embyGetUserDetail(serverURL, apiKey, userID string) (embyUserDetail, error) {
	u := strings.TrimSuffix(serverURL, "/") + "/Users/" + userID
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf(`MediaBrowser Token="%s"`, apiKey))
		req.Header.Set("X-MediaBrowser-Token", apiKey)
	}
	if Debugf != nil {
		Debugf("emby/user GET %s (apiKey=%v)", u, apiKey != "")
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return embyUserDetail{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		snippet := string(raw)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		if Warnf != nil {
			Warnf("emby/user HTTP %d body=%q", resp.StatusCode, snippet)
		}
		return embyUserDetail{}, fmt.Errorf("emby user %d: %s", resp.StatusCode, snippet)
	}
	var out embyUserDetail
	if err := json.Unmarshal(raw, &out); err != nil {
		if Warnf != nil {
			Warnf("emby/user decode failed: %v body=%q", err, string(raw))
		}
		return embyUserDetail{}, fmt.Errorf("emby user decode failed: %w", err)
	}
	return out, nil
}
