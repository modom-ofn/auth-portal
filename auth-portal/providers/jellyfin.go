package providers

import (
    "context"
    "fmt"
    "html"
    "log"
	"net/http"
	"strings"
)

// Jellyfin uses the same MediaBrowser header schema as Emby.

type JellyfinProvider struct{}

func (JellyfinProvider) Name() string { return "jellyfin" }

// Optional health check: ensure base URL configured
func (JellyfinProvider) Health() error {
	if strings.TrimSpace(JellyfinServerURL) == "" {
		return fmt.Errorf("JellyfinServerURL is empty")
	}
	return nil
}

// CompleteOutcome provides a structured result (no cookie writes).
func (JellyfinProvider) CompleteOutcome(_ context.Context, r *http.Request) (AuthOutcome, *HTTPResult, error) {
	// Serve login form on GET
	if r.Method == http.MethodGet {
		hdr := http.Header{}
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		body := []byte(`<html><head><title>Jellyfin Login</title></head><body style="font-family:system-ui;padding:2rem">
              <h1 style="margin-bottom:1rem"><img src="/static/jellyfin.svg" alt="Jellyfin" width="24" height="24" /> Sign in to Jellyfin</h1>
              <form method="post" action="/auth/forward?jellyfin=1" class="card" style="padding:1rem">
                <label>Username<br><input name="username" autocomplete="username" required></label><br><br>
                <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br><br>
                <button type="submit">Sign In</button>
                <p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(JellyfinServerURL) + `</p>
              </form></body></html>`)
		return AuthOutcome{}, &HTTPResult{Status: http.StatusOK, Header: hdr, Body: body}, nil
	}

	if err := r.ParseForm(); err != nil {
		return AuthOutcome{}, nil, fmt.Errorf("invalid form")
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		hdr := http.Header{}
		hdr.Set("Location", "/auth/forward?jellyfin=1")
		return AuthOutcome{}, &HTTPResult{Status: http.StatusSeeOther, Header: hdr}, nil
	}

	clientID := randClientID()
	auth, err := jellyfinAuthenticate(JellyfinServerURL, clientID, username, password)
	if err != nil {
		if Warnf != nil {
			Warnf("jellyfin/auth Pw failed: %v", err)
		}
		// Inline retry page
		hdr := http.Header{}
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		body := []byte(`<html><head><title>Jellyfin Login Failed</title></head><body style="font-family:system-ui;padding:2rem">
                      <h1 style="margin-bottom:1rem"><img src="/static/jellyfin.svg" alt="Jellyfin" width="24" height="24" /> Sign in to Jellyfin</h1>
                      <form method="post" action="/auth/forward?jellyfin=1">
                        <p style="color:red">Login failed; please try again.</p>
                        <label>Username<br><input name="username" value="` + html.EscapeString(username) + `" autocomplete="username" required></label><br><br>
                        <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br><br>
                        <button type="submit">Sign In</button>
                        <a href="/auth/forward?jellyfin=1" class="muted">Reset</a>
                        <p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(JellyfinServerURL) + `</p>
                      </form></body></html>`)
		return AuthOutcome{}, &HTTPResult{Status: http.StatusUnauthorized, Header: hdr, Body: body}, nil
	}

	md, _ := mediaGetUserDetail("jellyfin", JellyfinServerURL, auth.AccessToken, auth.User.ID)
	authorized := false
	if JellyfinAPIKey != "" && md.ID != "" && !md.Policy.IsDisabled {
		authorized = true
	}

	sealedToken, serr := SealToken(auth.AccessToken)
	if serr != nil {
		log.Printf("WARN: jellyfin token seal failed: %v", serr)
		sealedToken = ""
	}
	mediaUUID := "jellyfin-" + auth.User.ID

	return AuthOutcome{
		Provider:    "jellyfin",
		Username:    auth.User.Name,
		Email:       "",
		MediaUUID:   mediaUUID,
		SealedToken: sealedToken,
		Authorized:  authorized,
	}, nil, nil
}

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
            Provider:    "jellyfin",
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

func jellyfinAuthenticate(serverURL, clientID, username, password string) (mediaAuthResp, error) {
	base := strings.TrimSuffix(serverURL, "/")
	if Debugf != nil {
		Debugf("jellyfin/auth start server=%s user=%q", base, username)
	}
	out, err := mediaAuthAttempt("jellyfin", base, JellyfinAppName, JellyfinAppVersion, clientID, map[string]string{
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
	out2, err2 := mediaAuthAttempt("jellyfin", base, JellyfinAppName, JellyfinAppVersion, clientID, map[string]string{
		"pw":       password,
		"username": username,
	})
	if err2 == nil {
		if Debugf != nil {
			Debugf("jellyfin/auth success (Password) userID=%s", out2.User.ID)
		}
		return out2, nil
	}
	return mediaAuthResp{}, err2
}

func jellyfinTokenStillValid(serverURL, token string) (bool, error) { return mediaTokenStillValid("jellyfin", serverURL, token) }

// Legacy compatibility wrappers (used by legacy Forward/IsAuthorized paths)
type jellyfinUserDetail = mediaUserDetail
func jellyfinGetUserDetail(serverURL, token, userID string) (jellyfinUserDetail, error) {
    return mediaGetUserDetail("jellyfin", serverURL, token, userID)
}
