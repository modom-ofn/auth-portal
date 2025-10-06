package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Minimal shape returned by /Users/Me
type embyMe struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
}

type EmbyProvider struct{}

func embyLoginPageHTML(prefill, errorMsg string) []byte {
	escaped := html.EscapeString(strings.TrimSpace(prefill))

	errSnippet := ""
	if msg := strings.TrimSpace(errorMsg); msg != "" {
		errSnippet = fmt.Sprintf(`
      <div class="alert error">%s</div>`, html.EscapeString(msg))
	}

	return []byte(fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AuthPortal - Emby Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/static/styles.css">
  <style>
    html, body { height: 100%%; overflow: hidden; }
    body::before, body::after { display: none; }
    [data-scroll], [data-scroll]::before { display: none; }
    .page { min-height: auto; padding: 0; }
    main.center { width: 100vw; }
    body { margin: 0; overflow: hidden; }
    main.center { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 0; }
    .auth-modal { max-width: 360px; padding: 2rem; display: flex; flex-direction: column; gap: 1rem; }
    .auth-modal h1 { margin: 0; font-size: 1.5rem; }
    .auth-modal form label { display: block; margin-bottom: 0.75rem; font-weight: 500; }
    .auth-modal input { width: 100%%; margin-top: 0.35rem; padding: 0.6rem 0.75rem; border-radius: 0.5rem; border: 1px solid #d1d5db; background: #f9fafb; }
    .auth-modal button { width: 100%%; margin-top: 0.5rem; }
    .alert.error { background: #fee2e2; color: #991b1b; border-radius: 0.75rem; padding: 0.75rem 1rem; font-size: 0.9rem; }
    .modal-header { display: flex; align-items: center; gap: 0.75rem; }
    .modal-header img { display: block; }
  </style>
</head>
<body class="bg">
  <main class="center">
    <section class="card auth-modal">
      <div class="modal-header">
        <img src="/static/emby.svg" alt="Emby" width="36" height="36" />
        <div>
          <h1>Sign in to Emby</h1>
          <p class="muted" style="margin: 0;">Use your Emby credentials to continue.</p>
        </div>
      </div>%s
      <form method="post" action="/auth/forward?emby=1" class="modal-form">
        <label>Username<br><input name="username" value="%s" autocomplete="username" required></label>
        <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label>
        <button type="submit" class="btn primary">Sign In</button>
      </form>
    </section>
  </main>
</body>
</html>`, errSnippet, escaped))
}

func (EmbyProvider) Name() string { return "emby" }

// Optional health check: ensure base URL configured
func (EmbyProvider) Health() error {
	if strings.TrimSpace(EmbyServerURL) == "" {
		return fmt.Errorf("EmbyServerURL is empty")
	}
	return nil
}

// CompleteOutcome provides a structured result (no cookie writes).
func (EmbyProvider) CompleteOutcome(_ context.Context, r *http.Request) (AuthOutcome, *HTTPResult, error) {
	if r.Method == http.MethodGet {
		hdr := http.Header{}
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		body := embyLoginPageHTML("", "")
		return AuthOutcome{}, &HTTPResult{Status: http.StatusOK, Header: hdr, Body: body}, nil
	}

	if err := r.ParseForm(); err != nil {
		return AuthOutcome{}, nil, fmt.Errorf("invalid form")
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		hdr := http.Header{}
		hdr.Set("Location", "/auth/forward?emby=1")
		return AuthOutcome{}, &HTTPResult{Status: http.StatusSeeOther, Header: hdr}, nil
	}

	clientID := randClientID()
	auth, err := embyAuthenticate(EmbyServerURL, clientID, username, password)
	if err != nil {
		if Warnf != nil {
			Warnf("emby/auth Pw failed: %v", err)
		}
		hdr := http.Header{}
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		body := embyLoginPageHTML(username, "Login failed; please try again.")
		return AuthOutcome{}, &HTTPResult{Status: http.StatusUnauthorized, Header: hdr, Body: body}, nil
	}

	var md mediaUserDetail
	var detailErr error
	if strings.TrimSpace(EmbyAPIKey) != "" {
		md, detailErr = mediaGetUserDetail("emby", EmbyServerURL, EmbyAPIKey, auth.User.ID)
	} else {
		md, detailErr = mediaGetUserDetail("emby", EmbyServerURL, auth.AccessToken, auth.User.ID)
	}
	if detailErr != nil {
		if Warnf != nil {
			Warnf("emby detail fetch failed for %s: %v", auth.User.Name, detailErr)
		}
	}

	authorized := false
	if owner := strings.TrimSpace(EmbyOwnerUsername); owner != "" && strings.EqualFold(auth.User.Name, owner) {
		authorized = true
	}
	if ownerID := strings.TrimSpace(EmbyOwnerID); ownerID != "" && auth.User.ID == ownerID {
		authorized = true
	}
	if md.ID != "" && !md.Policy.IsDisabled {
		authorized = true
	}

	sealedToken, serr := SealToken(auth.AccessToken)
	if serr != nil {
		log.Printf("WARN: emby token seal failed: %v", serr)
		sealedToken = ""
	}
	mediaUUID := "emby-" + auth.User.ID

	if UpsertUser != nil {
		err := UpsertUser(User{
			Username:    auth.User.Name,
			Email:       "",
			MediaUUID:   mediaUUID,
			MediaToken:  sealedToken,
			MediaAccess: authorized,
			Provider:    "emby",
		})
		if err != nil && Warnf != nil {
			Warnf("emby upsert failed for %s: %v", auth.User.Name, err)
		}
	}

	return AuthOutcome{
		Provider:    "emby",
		Username:    auth.User.Name,
		Email:       "",
		MediaUUID:   mediaUUID,
		SealedToken: sealedToken,
		Authorized:  authorized,
	}, nil, nil
}

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
		_, _ = w.Write(embyLoginPageHTML("", ""))
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
		_, _ = w.Write(embyLoginPageHTML(username, "Login failed; please try again."))
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
			Provider:    "emby",
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
	return mediaTokenStillValid("emby", serverURL, token)
}

// Legacy compatibility wrappers (used by legacy Forward/IsAuthorized paths)
type embyUserDetail = mediaUserDetail

func embyGetUserDetail(serverURL, token, userID string) (embyUserDetail, error) {
	return mediaGetUserDetail("emby", serverURL, token, userID)
}

func embyAuthenticate(serverURL, clientID, username, password string) (mediaAuthResp, error) {
	base := strings.TrimSuffix(serverURL, "/")
	if Debugf != nil {
		Debugf("emby/auth start server=%s user=%q", base, username)
	}
	// Try the form-style keys first (matches Emby Web patterns)
	out, err := mediaAuthAttempt("emby", base, EmbyAppName, EmbyAppVersion, clientID, map[string]string{
		"pw":       password,
		"username": username,
	})
	if err == nil {
		if Debugf != nil {
			Debugf("emby/auth success (pw) userID=%s", out.User.ID)
		}
		return out, nil
	}
	if Debugf != nil {
		Debugf("emby/auth (pw) attempt failed: %v", err)
	}
	// Fallback to Username/Password JSON body
	out2, err2 := mediaAuthAttempt("emby", base, EmbyAppName, EmbyAppVersion, clientID, map[string]string{
		"Username": username,
		"Password": password,
	})
	if err2 == nil {
		if Debugf != nil {
			Debugf("emby/auth success (Password) userID=%s", out2.User.ID)
		}
		return out2, nil
	}
	return mediaAuthResp{}, err2
}

// embyGetMe fetches the current user info using an access token.
func embyGetMe(serverURL, token string) (embyMe, error) {
	var out embyMe
	req, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(serverURL, "/")+"/Users/Me", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Emby-Token", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("emby me %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

// old specific helpers replaced by shared httpx helpers
