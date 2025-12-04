package providers

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

// Jellyfin uses the same MediaBrowser header schema as Emby.

type JellyfinProvider struct{}

const (
	jellyfinForwardPath       = "/auth/forward?jellyfin=1"
	jellyfinHeaderContentType = "Content-Type"
	jellyfinContentTypeHTML   = "text/html; charset=utf-8"
	jellyfinPwFailedFormat    = "jellyfin/auth Pw failed: %v"
	jellyfinMediaPrefix       = "jellyfin-"
)

var errJellyfinMissingCredentials = errors.New("missing credentials")

type jellyfinCredentials struct {
	username string
	password string
}

type jellyfinAuthData struct {
	authorized bool
	admin      bool
}

func jellyfinLoginPageHTML(prefill, errorMsg string) []byte {
	escaped := html.EscapeString(strings.TrimSpace(prefill))

	errSnippet := ""
	if msg := strings.TrimSpace(errorMsg); msg != "" {
		errSnippet = fmt.Sprintf(`
      <div class="alert error">%s</div>`, html.EscapeString(msg))
	}

	resetSnippet := ""
	if errSnippet != "" {
		resetSnippet = fmt.Sprintf(`
        <a href="%s" class="muted" style="display:inline-block; margin-top:0.75rem;">Reset</a>`, jellyfinForwardPath)
	}

	serverSnippet := ""
	if server := strings.TrimSpace(JellyfinServerURL); server != "" {
		serverSnippet = fmt.Sprintf(`
        <p class="muted" style="margin-top:0.75rem; font-size:0.9rem;">Server: %s</p>`, htmlEscape(server))
	}

	return []byte(fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AuthPortal - Jellyfin Login</title>
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
        <img src="/static/jellyfin.svg" alt="Jellyfin" width="36" height="36" />
        <div>
          <h1>Sign in to Jellyfin</h1>
          <p class="muted" style="margin: 0;">Use your Jellyfin credentials to continue.</p>
        </div>
      </div>%s
      <form method="post" action="%s" class="modal-form">
        <label>Username<br><input name="username" value="%s" autocomplete="username" required></label>
        <label>Password<br><input type="password" name="password" autocomplete="current-password" required></label>
        <button type="submit" class="btn primary">Sign In</button>%s%s
      </form>
    </section>
  </main>
</body>
</html>`, errSnippet, jellyfinForwardPath, escaped, resetSnippet, serverSnippet))
}

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
		hdr.Set(jellyfinHeaderContentType, jellyfinContentTypeHTML)
		body := jellyfinLoginPageHTML("", "")
		return AuthOutcome{}, &HTTPResult{Status: http.StatusOK, Header: hdr, Body: body}, nil
	}

	if err := r.ParseForm(); err != nil {
		return AuthOutcome{}, nil, fmt.Errorf("invalid form: %w", err)
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		hdr := http.Header{}
		hdr.Set("Location", jellyfinForwardPath)
		return AuthOutcome{}, &HTTPResult{Status: http.StatusSeeOther, Header: hdr}, nil
	}

	clientID := randClientID()
	auth, err := jellyfinAuthenticate(JellyfinServerURL, clientID, username, password)
	if err != nil {
		if Warnf != nil {
			Warnf(jellyfinPwFailedFormat, err)
		}
		// Inline retry page
		hdr := http.Header{}
		hdr.Set(jellyfinHeaderContentType, jellyfinContentTypeHTML)
		body := jellyfinLoginPageHTML(username, "Login failed; please try again.")
		return AuthOutcome{}, &HTTPResult{Status: http.StatusUnauthorized, Header: hdr, Body: body}, nil
	}

	md, detailErr := jellyfinUserDetailForAuth(auth)
	if detailErr != nil && Warnf != nil {
		Warnf("jellyfin/auth user detail lookup failed: %v", detailErr)
	}
	authorized := md.ID != "" && !md.Policy.IsDisabled
	admin := authorized && (md.Policy.IsAdministrator || md.Policy.IsAdmin)
	jellyfinSyncAdminAccess(auth.User.Name, admin)

	sealedToken, serr := SealToken(auth.AccessToken)
	if serr != nil {
		log.Printf("WARN: jellyfin token seal failed: %v", serr)
		sealedToken = ""
	}
	mediaUUID := jellyfinMediaPrefix + auth.User.ID

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
func (JellyfinProvider) StartWeb(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "jellyfin",
		"authUrl":  jellyfinForwardPath,
	})
}

func (JellyfinProvider) Forward(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderJellyfinLogin(w, http.StatusOK, "", "")
		return
	}

	creds, err := jellyfinParseCredentials(r)
	if err != nil {
		handleJellyfinCredentialError(w, r, err)
		return
	}

	clientID := randClientID()
	auth, err := jellyfinAuthenticate(JellyfinServerURL, clientID, creds.username, creds.password)
	if err != nil {
		logJellyfinPwFailure(err)
		renderJellyfinLogin(w, http.StatusUnauthorized, creds.username, "Login failed; please try again.")
		return
	}

	if Debugf != nil {
		Debugf("jellyfin/auth success userID=%s", auth.User.ID)
	}
	if ok, terr := jellyfinTokenStillValid(JellyfinServerURL, auth.AccessToken); terr == nil && ok {
		if Debugf != nil {
			Debugf("jellyfin/auth token valid for %s", creds.username)
		}
	}

	md, detailErr := jellyfinUserDetailForAuth(auth)
	if detailErr != nil && Warnf != nil {
		Warnf("jellyfin detail fetch failed for %s: %v", creds.username, detailErr)
	}
	authz := jellyfinAuthData{
		authorized: md.ID != "" && !md.Policy.IsDisabled,
		admin:      md.ID != "" && !md.Policy.IsDisabled && (md.Policy.IsAdministrator || md.Policy.IsAdmin),
	}
	sealedToken := jellyfinSealedToken(auth.AccessToken)
	mediaUUID := jellyfinMediaPrefix + auth.User.ID

	jellyfinPersistUser(mediaUUID, auth.User.Name, sealedToken, authz.authorized)
	jellyfinSyncAdminAccess(auth.User.Name, authz.admin)
	jellyfinSetSession(w, mediaUUID, auth.User.Name, authz.authorized)

	WriteAuthCompletePage(w, AuthCompletePageOptions{
		Message:  "Signed in - you can close this window.",
		Provider: "jellyfin-auth",
		Redirect: "/home",
	})
}

func (JellyfinProvider) IsAuthorized(uuid, _ string) (bool, error) {
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
		id := strings.TrimPrefix(u.MediaUUID, jellyfinMediaPrefix)
		if detail, derr := jellyfinGetUserDetail(JellyfinServerURL, JellyfinAPIKey, id); derr == nil {
			ok := !detail.Policy.IsDisabled
			if SetUserMediaAccessByUsername != nil {
				if setErr := SetUserMediaAccessByUsername(u.Username, ok); setErr != nil && Warnf != nil {
					Warnf("jellyfin set media access failed for %s: %v", u.Username, setErr)
				}
			}
			return ok, nil
		}
	}
	return false, nil
}

func jellyfinParseCredentials(r *http.Request) (jellyfinCredentials, error) {
	if err := r.ParseForm(); err != nil {
		return jellyfinCredentials{}, fmt.Errorf("parse form: %w", err)
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		return jellyfinCredentials{}, errJellyfinMissingCredentials
	}
	return jellyfinCredentials{username: username, password: password}, nil
}

func handleJellyfinCredentialError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errJellyfinMissingCredentials) {
		http.Redirect(w, r, jellyfinForwardPath, http.StatusSeeOther)
		return
	}
	http.Error(w, "invalid form", http.StatusBadRequest)
}

func logJellyfinPwFailure(err error) {
	if Warnf != nil {
		Warnf(jellyfinPwFailedFormat, err)
		return
	}
	log.Printf("WARN: "+jellyfinPwFailedFormat, err)
}

func jellyfinUserDetailForAuth(auth mediaAuthResp) (jellyfinUserDetail, error) {
	token := strings.TrimSpace(JellyfinAPIKey)
	if token == "" {
		token = strings.TrimSpace(auth.AccessToken)
	}
	return jellyfinGetUserDetail(JellyfinServerURL, token, auth.User.ID)
}

func jellyfinSealedToken(token string) string {
	sealedToken, err := SealToken(token)
	if err != nil {
		log.Printf("WARN: jellyfin token seal failed: %v", err)
		return ""
	}
	return sealedToken
}

func jellyfinPersistUser(mediaUUID, username, sealedToken string, authorized bool) {
	if UpsertUser == nil {
		return
	}
	if err := UpsertUser(User{
		Username:    username,
		Email:       "",
		MediaUUID:   mediaUUID,
		MediaToken:  sealedToken,
		MediaAccess: authorized,
		Provider:    "jellyfin",
	}); err != nil && Warnf != nil {
		Warnf("jellyfin upsert user failed for %s: %v", username, err)
	}
}

func jellyfinSyncAdminAccess(username string, admin bool) {
	if SetUserAdminByUsername == nil {
		return
	}
	if err := SetUserAdminByUsername(username, admin); err != nil && Warnf != nil {
		Warnf("jellyfin admin sync failed for %s: %v", username, err)
	}
}

func jellyfinSetSession(w http.ResponseWriter, mediaUUID, username string, authorized bool) {
	if authorized {
		if SetSessionCookie != nil {
			if err := SetSessionCookie(w, mediaUUID, username); err != nil && Warnf != nil {
				Warnf("jellyfin session cookie set failed: %v", err)
			}
		}
		return
	}
	if SetTempSessionCookie != nil {
		if err := SetTempSessionCookie(w, mediaUUID, username); err != nil && Warnf != nil {
			Warnf("jellyfin temp session cookie set failed: %v", err)
		}
	}
}

func renderJellyfinLogin(w http.ResponseWriter, status int, prefill, message string) {
	w.Header().Set(jellyfinHeaderContentType, jellyfinContentTypeHTML)
	w.WriteHeader(status)
	if _, err := w.Write(jellyfinLoginPageHTML(prefill, message)); err != nil {
		log.Printf("WARN: jellyfin login page write failed: %v", err)
	}
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
		Warnf(jellyfinPwFailedFormat, err)
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

func jellyfinTokenStillValid(serverURL, token string) (bool, error) {
	return mediaTokenStillValid("jellyfin", serverURL, token)
}

// Legacy compatibility wrappers (used by legacy Forward/IsAuthorized paths)
type jellyfinUserDetail = mediaUserDetail

func jellyfinGetUserDetail(serverURL, token, userID string) (jellyfinUserDetail, error) {
	return mediaGetUserDetail("jellyfin", serverURL, token, userID)
}
