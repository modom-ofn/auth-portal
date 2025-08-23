package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/************* Provider interface (unchanged) *************/
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

/* =======================================================
 *                        PLEX
 * ======================================================= */

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
func plexGetJSON(url, token string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Token", token)
	// Friendly identification (optional)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0.0")
	req.Header.Set("X-Plex-Client-Identifier", "auth-portal")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s := strings.TrimSpace(string(body))
		if len(s) > 200 { s = s[:200] + "…" }
		return fmt.Errorf("plex %s -> %d: %s", url, resp.StatusCode, s)
	}
	return json.Unmarshal(body, out)
}

// Does this token's account see the configured server?
func plexUserHasServer(token string) (bool, error) {
	url := "https://plex.tv/api/resources?includeHttps=1"
	var devices []plexResource
	if err := plexGetJSON(url, token, &devices); err != nil {
		return false, err
	}

	mid := strings.TrimSpace(plexServerMachineID)
	sname := strings.TrimSpace(plexServerName)

	for _, d := range devices {
		// "provides" is a comma-separated string; we only care about "server"
		if !strings.Contains(strings.ToLower(d.Provides), "server") {
			continue
		}
		if mid != "" && strings.EqualFold(d.ClientIdentifier, mid) {
			return true, nil
		}
		if sname != "" && strings.EqualFold(d.Name, sname) {
			return true, nil
		}
	}
	return false, nil
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

// plexUserHasServer: true if user's token can see configured server in /resources
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

type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

// StartWeb: create PIN → return Plex UI URL
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
		"ok":         true, "provider": "plex",
		"authUrl":    authURL,
		"pin_id":     pin.ID, "client_id": clientID, "expires_in": 120,
	})
}

// Forward: finish login (Plex) and close popup
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

	token, err := plexPollPin(clientID, pinID, 60*time.Second)
	if err != nil || token == "" {
		// show waiting page instead of blank
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><title>Plex: Waiting…</title><body style="font-family:system-ui;padding:2rem"><h1>Waiting for Plex approval…</h1></body>`))
		return
	}

	// 2) Fetch user info
	user, _ := plexFetchUser(token)
	username := user.Username
	if username == "" {
		username = "plex-user"
	}
	mediaUUID := fmt.Sprintf("plex-%d", user.ID)
	email := user.Email

	// 3) Seal token for storage
	sealedToken, err := SealToken(token)
	if err != nil {
		log.Printf("WARN: token seal failed: %v (storing empty token)", err)
		sealedToken = ""
	}

	// 4) Check authorization: can *this user* see your server in /resources?
	authorized := false
	if strings.TrimSpace(plexServerMachineID) != "" || strings.TrimSpace(plexServerName) != "" {
		if ok, _ := plexUserHasServer(token); ok {
			authorized = true
		}
	} else if strings.TrimSpace(plexOwnerToken) != "" {
		if uid, e1 := plexAccountID(token); e1 == nil {
			if oid, e2 := plexAccountID(plexOwnerToken); e2 == nil && uid == oid {
				authorized = true
			}
		}
	}

	// 5) Persist (media_* fields)
	_, _ = upsertUser(User{
		Username:    username,
		Email:       nullStringFrom(email),
		MediaUUID:   nullStringFrom(fmt.Sprintf("plex-%d", user.ID)),
		MediaToken:  nullStringFrom(sealedToken),
		MediaAccess: authorized,
	})

	// 6) Session + finish page stays as you had it...
	if authorized {
		_ = setSessionCookie(w, mediaUUID, username)
	} else {
		_ = setTempSessionCookie(w, mediaUUID, username)
	}

	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>Signed in — AuthPortal</title><body style="font-family:system-ui;padding:2rem"><h1>Signed in — you can close this window.</h1><script>try{if(window.opener&&!window.opener.closed){window.opener.postMessage({ok:true,type:"plex-auth",redirect:"/home"},window.location.origin)}}catch(e){};setTimeout(()=>{try{window.close()}catch(e){}},600);</script></body>`))
}

func (plexProvider) IsAuthorized(uuid, _username string) (bool, error) {
	u, err := getUserByUUID(uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	// Trust cache
	if u.MediaAccess {
		return true, nil
	}

	// Need a token to check live.
	if !u.MediaToken.Valid || strings.TrimSpace(u.MediaToken.String) == "" {
		return false, nil
	}
	userToken := strings.TrimSpace(u.MediaToken.String)

	// 1) Preferred: check if this user can see the configured server
	if strings.TrimSpace(plexServerMachineID) != "" || strings.TrimSpace(plexServerName) != "" {
		ok, err := plexUserHasServer(userToken)
		if err == nil {
			if ok {
				_ = setUserMediaAccessByUsername(u.Username, true)
			}
			return ok, nil
		}
		Debugf("plex: server visibility check failed: %v", err)
	}

	// 2) Fallback: if we have an owner token, consider the owner always authorized
	if strings.TrimSpace(plexOwnerToken) != "" {
		usrID, e1 := plexAccountID(userToken)
		ownID, e2 := plexAccountID(plexOwnerToken)
		if e1 == nil && e2 == nil && usrID != "" && usrID == ownID {
			_ = setUserMediaAccessByUsername(u.Username, true)
			return true, nil
		}
	}

	return false, nil
}


/* =======================================================
 *                        EMBY
 * ======================================================= */

var (
	embyServerURL     = envOr("EMBY_SERVER_URL", "http://localhost:8096")
	embyAppName       = envOr("EMBY_APP_NAME", "AuthPortal")
	embyAppVersion    = envOr("EMBY_APP_VERSION", "1.0.0")
	embyAPIKey        = envOr("EMBY_API_KEY", "")
	embyOwnerUsername = envOr("EMBY_OWNER_USERNAME", "")
	embyOwnerID       = envOr("EMBY_OWNER_ID", "")
)

// Build the MediaBrowser auth header used by Emby
func embyAuthHeader(clientID string) string {
	return fmt.Sprintf(`MediaBrowser Client="%s", Device="Web", DeviceId="%s", Version="%s"`,
		embyAppName, clientID, embyAppVersion)
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

type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }

// StartWeb: tell the client to open our own login form popup (/auth/forward?emby=1)
func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "emby",
		"authUrl":  "/auth/forward?emby=1",
	})
}

// Forward (GET): render small login form; (POST): authenticate → set cookie → close
func (embyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		page := `<!doctype html>
	<html lang="en">
	<head>
	  <meta charset="utf-8" />
	  <title>Sign in to Emby — AuthPortal</title>
	  <meta name="viewport" content="width=device-width, initial-scale=1" />
	  <link rel="stylesheet" href="/static/styles.css" />
	</head>
	<body class="bg">
	  <main class="container" style="max-width:28rem;margin:2rem auto">
		<header style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem">
		  <img src="/static/emby.svg" alt="Emby" width="24" height="24" />
		  <h1 class="title" style="margin:0;font-size:1.25rem">Sign in to Emby</h1>
		</header>

		<p class="subtitle" style="margin:.25rem 0 1rem">Continue to <strong>AuthPortal</strong></p>

		<form method="post" action="/auth/forward?emby=1" class="card" style="padding:1rem">
		  <label style="display:block;margin:.5rem 0">
			<span>Username</span><br/>
			<input name="username" required autofocus style="width:100%;padding:.5rem"/>
		  </label>
		  <label style="display:block;margin:.5rem 0">
			<span>Password</span><br/>
			<input type="password" name="password" required style="width:100%;padding:.5rem"/>
		  </label>
		  <button type="submit" class="btn" style="margin-top:.75rem">Sign in</button>
		</form>

		<p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(embyServerURL) + `</p>
	  </main>
	</body>
	</html>`
		_, _ = w.Write([]byte(page))
		return
	}

	// POST: authenticate with Emby
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "missing credentials", http.StatusBadRequest)
		return
	}

	clientID := randClientID()
	auth, err := embyAuthenticate(embyServerURL, clientID, username, password)
	if err != nil || auth.AccessToken == "" || auth.User.ID == "" {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)

		page := `<!doctype html>
		<html lang="en">
		<head>
		  <meta charset="utf-8" />
		  <title>Emby sign-in failed — AuthPortal</title>
		  <meta name="viewport" content="width=device-width, initial-scale=1" />
		  <link rel="stylesheet" href="/static/styles.css" />
		</head>
		<body class="bg">
		  <main class="container" style="max-width:28rem;margin:2rem auto">
			<header style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem">
			  <img src="/static/emby.svg" alt="Emby" width="24" height="24" />
			  <h1 class="title" style="margin:0;font-size:1.25rem">Sign in to Emby</h1>
			</header>

			<div class="card" style="padding:1rem">
			  <p class="error" style="color:#b91c1c;margin:0 0 .75rem"><strong>Login failed.</strong> Please try again.</p>
			  <form method="post" action="/auth/forward?emby=1">
				<label style="display:block;margin:.5rem 0">
				  <span>Username</span><br/>
				  <input name="username" required autofocus style="width:100%;padding:.5rem"/>
				</label>
				<label style="display:block;margin:.5rem 0">
				  <span>Password</span><br/>
				  <input type="password" name="password" required style="width:100%;padding:.5rem"/>
				</label>
				<div style="display:flex;gap:.5rem;align-items:center;margin-top:.75rem">
				  <button type="submit" class="btn">Try again</button>
				  <a href="/auth/forward?emby=1" class="muted">Reset</a>
				</div>
			  </form>
			</div>

			<p class="muted" style="margin-top:.75rem">Server: ` + htmlEscape(embyServerURL) + `</p>
		  </main>
		</body>
		</html>`
		_, _ = w.Write([]byte(page))
		return
	}

	// Optional: verify status with API key (recommended)
	// Decide authorization
	authorized := true
	if embyAPIKey != "" {
		detail, derr := embyGetUserDetail(embyServerURL, embyAPIKey, auth.User.ID)
		if derr != nil {
			log.Printf("emby detail fetch failed for %s: %v", auth.User.Name, derr)
			authorized = false // conservative
		} else {
			authorized = !detail.Policy.IsDisabled
		}
	}

	// Seal token
	sealedToken, serr := SealToken(auth.AccessToken)
	if serr != nil {
		log.Printf("WARN: emby token seal failed: %v", serr)
		sealedToken = ""
	}

	// Compose media UUID
	mediaUUID := "emby-" + auth.User.ID

	// Persist (media_* fields)
	_, _ = upsertUser(User{
		Username:    auth.User.Name,
		Email:       sql.NullString{},           // Emby typically doesn’t return email here
		MediaUUID:   nullStringFrom(mediaUUID),
		MediaToken:  nullStringFrom(sealedToken),
		MediaAccess: authorized,
	})

	// Session
	if authorized {
		_ = setSessionCookie(w, mediaUUID, auth.User.Name)
	} else {
		_ = setTempSessionCookie(w, mediaUUID, auth.User.Name)
	}

	// Finish popup
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
	<title>Signed in — AuthPortal</title>
	<link rel="stylesheet" href="/static/styles.css" />
	<body class="bg">
	  <main class="container" style="max-width:28rem;margin:2rem auto">
		<header style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem">
		  <img src="/static/emby.svg" alt="Emby" width="24" height="24" />
		  <h1 class="title" style="margin:0;font-size:1.25rem">Signed in to Emby</h1>
		</header>
		<p>You can close this window.</p>
	  </main>
	  <script>
		try {
		  if (window.opener && !window.opener.closed) {
			window.opener.postMessage({ ok: true, type: "emby-auth", redirect: "/home" }, window.location.origin);
		  }
		} catch (e) {}
		setTimeout(() => { try { window.close(); } catch(e){} }, 600);
	  </script>
	</body>`))
}

func (embyProvider) IsAuthorized(uuid, _username string) (bool, error) {
	u, err := getUserByUUID(uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	// Trust the cached DB flag if present.
	if u.MediaAccess {
		return true, nil
	}

	// If we have an owner API key, re-check the user's current state and cache.
	if embyAPIKey != "" && u.MediaUUID.Valid {
		id := strings.TrimPrefix(u.MediaUUID.String, "emby-")
		if id != "" {
			detail, derr := embyGetUserDetail(embyServerURL, embyAPIKey, id)
			if derr == nil {
				ok := !detail.Policy.IsDisabled
				_ = setUserMediaAccessByUsername(u.Username, ok) // best-effort cache
				return ok, nil
			}
			// fall through to token-based fallback if available
		}
	}

	// Fallback: if we have the user's token, do a lightweight validity probe.
	if u.MediaToken.Valid && u.MediaToken.String != "" {
		if ok, derr := embyTokenStillValid(embyServerURL, u.MediaToken.String); derr == nil && ok {
			_ = setUserMediaAccessByUsername(u.Username, true) // cache success
			return true, nil
		}
	}

	return false, nil
}

// embyTokenStillValid checks whether the user's token is currently accepted by the server.
func embyTokenStillValid(serverURL, token string) (bool, error) {
	base := strings.TrimRight(serverURL, "/")
	req, _ := http.NewRequest(http.MethodGet, base+"/Users/Me?format=json", nil)
	req.Header.Set("X-Emby-Token", token)
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

/************* Emby HTTP helpers *************/

// Authenticate to Emby using Username+Pw (newer) or Username+Password (fallback).
func embyAuthenticate(serverURL, clientID, username, password string) (embyAuthResp, error) {
	base := strings.TrimRight(serverURL, "/")
	Debugf("emby/auth start server=%s user=%q", base, username)

	// 1) Try Username + Pw
	out, err := embyAuthAttempt(base, clientID, map[string]string{
		"Username": username,
		"Pw":       password, // never logged
	})
	if err == nil && out.AccessToken != "" && out.User.ID != "" {
		Debugf("emby/auth success (Pw) userID=%s", out.User.ID)
		return out, nil
	}
	if err != nil {
		Warnf("emby/auth Pw failed: %v", err)
	}

	// 2) Fallback Username + Password
	out2, err2 := embyAuthAttempt(base, clientID, map[string]string{
		"Username": username,
		"Password": password, // never logged
	})
	if err2 == nil && out2.AccessToken != "" && out2.User.ID != "" {
		Debugf("emby/auth success (Password) userID=%s", out2.User.ID)
		return out2, nil
	}
	// show the more specific error if available
	if err2 != nil {
		return embyAuthResp{}, err2
	}
	return embyAuthResp{}, fmt.Errorf("emby auth unknown failure")
}

// Single HTTP attempt for Emby auth. Adds ?format=json and sends both Authorization headers.
// DEBUG logs status and a short snippet of the response on non-2xx.
func embyAuthAttempt(baseURL, clientID string, body map[string]string) (embyAuthResp, error) {
	b, _ := json.Marshal(body)
	loginURL := baseURL + "/Users/AuthenticateByName?format=json"

	req, _ := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	authHdr := embyAuthHeader(clientID)
	req.Header.Set("X-Emby-Authorization", authHdr)
	req.Header.Set("Authorization", authHdr)

	req.Header.Set("X-Emby-Client", embyAppName)
	req.Header.Set("X-Emby-Device-Name", "Web")
	req.Header.Set("X-Emby-Device-Id", clientID)
	req.Header.Set("X-Emby-Client-Version", embyAppVersion)

	Debugf("emby/auth POST %s", loginURL)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return embyAuthResp{}, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		Warnf("emby/auth HTTP %d body=%q", resp.StatusCode, snippet)
		return embyAuthResp{}, fmt.Errorf("emby auth %d: %s", resp.StatusCode, snippet)
	}

	var out embyAuthResp
	if err := json.Unmarshal(raw, &out); err != nil {
		Warnf("emby/auth decode failed: %v body=%q", err, string(raw))
		return embyAuthResp{}, fmt.Errorf("emby auth decode failed: %w", err)
	}
	return out, nil
}

// Emby user details fetch
func embyGetUserDetail(serverURL, apiKey, userID string) (embyUserDetail, error) {
	base := strings.TrimRight(serverURL, "/")
	u := base + "/Users/" + url.PathEscape(userID) + "?format=json"
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	if apiKey != "" {
		req.Header.Set("X-Emby-Token", apiKey)
	}
	req.Header.Set("Accept", "application/json")

	Debugf("emby/user GET %s (apiKey=%v)", u, apiKey != "")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return embyUserDetail{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		Warnf("emby/user HTTP %d body=%q", resp.StatusCode, snippet)
		return embyUserDetail{}, fmt.Errorf("emby user %d: %s", resp.StatusCode, snippet)
	}
	var out embyUserDetail
	if err := json.Unmarshal(raw, &out); err != nil {
		Warnf("emby/user decode failed: %v body=%q", err, string(raw))
		return embyUserDetail{}, fmt.Errorf("emby user decode failed: %w", err)
	}
	return out, nil
}


/************* tiny util *************/
func htmlEscape(s string) string {
	repl := strings.NewReplacer(
		`&`, "&amp;",
		`<`, "&lt;",
		`>`, "&gt;",
		`"`, "&quot;",
		`'`, "&#39;",
	)
	return repl.Replace(s)
}