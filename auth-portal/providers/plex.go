package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

func plexSetStandardHeaders(req *http.Request, token, clientID string) {
	req.Header.Set("Accept", plexHeaderAcceptJSON)
	if token != "" {
		req.Header.Set(plexHeaderPlexToken, token)
	}
	req.Header.Set(plexHeaderPlexProduct, plexProductName)
	req.Header.Set(plexHeaderPlexVersion, plexProductVersion)
	if clientID != "" {
		req.Header.Set(plexHeaderPlexClientID, clientID)
	}
}

func plexReadBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read plex response body: %w", err)
	}
	return body, nil
}

const (
	plexHeaderAcceptJSON       = "application/json"
	plexHeaderContentType      = "Content-Type"
	plexHeaderPlexToken        = "X-Plex-Token"
	plexHeaderPlexProduct      = "X-Plex-Product"
	plexHeaderPlexVersion      = "X-Plex-Version"
	plexHeaderPlexClientID     = "X-Plex-Client-Identifier"
	plexPlexUserFallback       = "plex-user"
	plexMediaUUIDFormat        = "plex-%d"
	plexProductName            = "AuthPortal"
	plexProductVersion         = "2.0.0"
	plexClientIDDefault        = "auth-portal"
	plexClientIDUserInfo       = "authportal-userinfo"
	plexClientIDResourcesCheck = "authportal-check"
)

// GET JSON with standard Plex headers
func plexGetJSON(u, token string, out any) error {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("build plex request: %w", err)
	}
	plexSetStandardHeaders(req, token, plexClientIDDefault)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := plexReadBody(resp)
	if err != nil {
		return err
	}
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
		return plexPin{}, fmt.Errorf("build plex pin request: %w", err)
	}
	req.Header.Set(plexHeaderContentType, "application/x-www-form-urlencoded")
	req.Header.Set("Accept", plexHeaderAcceptJSON)
	req.Header.Set(plexHeaderPlexProduct, plexProductName)
	req.Header.Set(plexHeaderPlexVersion, plexProductVersion)
	req.Header.Set(plexHeaderPlexClientID, clientID)
	req.Header.Set("X-Plex-Device", "Web")
	req.Header.Set("X-Plex-Platform", "Web")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return plexPin{}, err
	}
	defer resp.Body.Close()
	body, err := plexReadBody(resp)
	if err != nil {
		return plexPin{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plexPin{}, fmt.Errorf("plex pins non-2xx: %d %s", resp.StatusCode, string(body))
	}
	var pin plexPin
	if err := json.Unmarshal(body, &pin); err != nil {
		return plexPin{}, fmt.Errorf("invalid plex pin response: %w", err)
	}
	if strings.TrimSpace(pin.Code) == "" {
		return plexPin{}, fmt.Errorf("invalid plex pin response: empty code")
	}
	return pin, nil
}

func plexPollPin(clientID string, id int, timeout time.Duration) (token string, err error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		token, ready, pollErr := plexPollPinOnce(clientID, id)
		if pollErr != nil && Debugf != nil {
			Debugf("plex pin poll error: %v", pollErr)
		}
		if ready && token != "" {
			return token, nil
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("timeout waiting for plex pin")
}

func plexPollPinOnce(clientID string, id int) (string, bool, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://plex.tv/api/v2/pins/%d", id), nil)
	if err != nil {
		return "", false, fmt.Errorf("build plex pin poll request: %w", err)
	}
	plexSetStandardHeaders(req, "", clientID)
	req.Header.Set("X-Plex-Device", "Web")
	req.Header.Set("X-Plex-Platform", "Web")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, err := plexReadBody(resp)
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("plex pin poll non-2xx: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var p plexPin
	if err := json.Unmarshal(body, &p); err != nil {
		return "", false, fmt.Errorf("decode plex pin: %w", err)
	}
	if p.AuthToken != "" {
		return p.AuthToken, true, nil
	}
	if p.AuthToken2 != "" {
		return p.AuthToken2, true, nil
	}
	return "", false, nil
}

func plexFetchUser(token string) (plexUser, error) {
	req, err := http.NewRequest(http.MethodGet, "https://plex.tv/api/v2/user", nil)
	if err != nil {
		return plexUser{}, fmt.Errorf("build plex user request: %w", err)
	}
	plexSetStandardHeaders(req, token, plexClientIDUserInfo)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return plexUser{}, err
	}
	defer resp.Body.Close()
	b, err := plexReadBody(resp)
	if err != nil {
		return plexUser{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return plexUser{}, fmt.Errorf("plex user non-2xx: %d %s", resp.StatusCode, string(b))
	}
	var u plexUser
	if err := json.Unmarshal(b, &u); err != nil {
		if Warnf != nil {
			Warnf("plex user decode failed: %v", err)
		}
		return plexUser{ID: 0, Username: plexPlexUserFallback}, nil
	}
	return u, nil
}

// plexUserHasServer: true if user's token can see configured server in /resources (v2)
func plexUserHasServer(userToken string) (bool, error) {
	if userToken == "" {
		return false, nil
	}
	rs, err := plexFetchResources(userToken)
	if err != nil {
		return false, err
	}
	return plexResourceMatchesConfiguredServer(rs, strings.TrimSpace(PlexServerMachineID), strings.TrimSpace(PlexServerName)), nil
}

func plexFetchResources(userToken string) ([]plexResource, error) {
	req, err := http.NewRequest(http.MethodGet, "https://plex.tv/api/v2/resources?includeHttps=1", nil)
	if err != nil {
		return nil, fmt.Errorf("build plex resources request: %w", err)
	}
	plexSetStandardHeaders(req, userToken, plexClientIDResourcesCheck)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := plexReadBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("resources non-2xx: %d %s", resp.StatusCode, string(body))
	}
	var rs []plexResource
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, err
	}
	return rs, nil
}

func plexResourceMatchesConfiguredServer(resources []plexResource, wantMID, wantName string) bool {
	for _, r := range resources {
		if !strings.Contains(r.Provides, "server") {
			continue
		}
		if wantMID != "" && r.ClientIdentifier == wantMID {
			return true
		}
		if wantName != "" && r.Name == wantName {
			return true
		}
	}
	return false
}

type PlexProvider struct{}

func (PlexProvider) Name() string { return "plex" }

// Optional health check: nothing to validate strictly; return nil.
func (PlexProvider) Health() error { return nil }

type plexPinCookie struct {
	id       int
	clientID string
}

type plexAuthData struct {
	username    string
	email       string
	mediaUUID   string
	sealedToken string
	authorized  bool
}

var errPlexPinNotReady = errors.New("plex pin not ready")

func plexParsePinCookie(r *http.Request) (plexPinCookie, error) {
	pc, err := r.Cookie("plex_pin")
	if err != nil {
		return plexPinCookie{}, fmt.Errorf("missing plex pin cookie: %w", err)
	}
	parts := strings.SplitN(pc.Value, ":", 3)
	if len(parts) < 2 {
		return plexPinCookie{}, fmt.Errorf("invalid plex pin cookie")
	}
	pinID, err := strconv.Atoi(parts[0])
	if err != nil {
		return plexPinCookie{}, fmt.Errorf("invalid plex pin id: %w", err)
	}
	clientID := ""
	if len(parts) >= 3 {
		clientID = strings.TrimSpace(parts[2])
	}
	if clientID == "" {
		clientID = randClientID()
	}
	return plexPinCookie{id: pinID, clientID: clientID}, nil
}

func plexAuthDataFromToken(token string) (plexAuthData, error) {
	user, err := plexFetchUser(token)
	if err != nil {
		return plexAuthData{}, err
	}
	username := strings.TrimSpace(user.Username)
	if username == "" {
		username = plexPlexUserFallback
	}
	email := strings.TrimSpace(user.Email)

	return plexAuthData{
		username:    username,
		email:       email,
		mediaUUID:   fmt.Sprintf(plexMediaUUIDFormat, user.ID),
		sealedToken: plexSealTokenForStorage(token),
		authorized:  plexTokenAuthorized(token),
	}, nil
}

func plexSealTokenForStorage(token string) string {
	sealedToken, err := SealToken(token)
	if err != nil {
		log.Printf("WARN: token seal failed: %v (storing empty token)", err)
		return ""
	}
	return sealedToken
}

func plexTokenAuthorized(token string) bool {
	if strings.TrimSpace(PlexServerMachineID) != "" || strings.TrimSpace(PlexServerName) != "" {
		ok, err := plexUserHasServer(token)
		if err != nil {
			if Warnf != nil {
				Warnf("plex: server visibility check failed: %v", err)
			}
			return false
		}
		return ok
	}

	if strings.TrimSpace(PlexOwnerToken) == "" {
		return false
	}

	usrID, userErr := plexAccountID(token)
	ownID, ownerErr := plexAccountID(PlexOwnerToken)
	if userErr == nil && ownerErr == nil && usrID != "" && usrID == ownID {
		return true
	}
	if Warnf != nil {
		if userErr != nil {
			Warnf("plex owner check (user) failed: %v", userErr)
		}
		if ownerErr != nil {
			Warnf("plex owner check (owner) failed: %v", ownerErr)
		}
	}
	return false
}

func plexResolveAuthData(r *http.Request, timeout time.Duration) (plexAuthData, error) {
	pin, err := plexParsePinCookie(r)
	if err != nil {
		return plexAuthData{}, err
	}
	token, err := plexPollPin(pin.clientID, pin.id, timeout)
	if err != nil || token == "" {
		if err == nil {
			if token == "" {
				return plexAuthData{}, errPlexPinNotReady
			}
			return plexAuthData{}, errPlexPinNotReady
		}
		return plexAuthData{}, err
	}
	return plexAuthDataFromToken(token)
}

func plexUpsertUserRecord(data plexAuthData) {
	if UpsertUser == nil {
		return
	}
	if err := UpsertUser(User{
		Username:    data.username,
		Email:       data.email,
		MediaUUID:   data.mediaUUID,
		MediaToken:  data.sealedToken,
		MediaAccess: data.authorized,
		Provider:    "plex",
	}); err != nil && Warnf != nil {
		Warnf("plex upsert user failed for %s: %v", data.username, err)
	}
}

func plexSetUserMediaAccess(username string, access bool) {
	if SetUserMediaAccessByUsername == nil {
		return
	}
	if err := SetUserMediaAccessByUsername(username, access); err != nil && Warnf != nil {
		Warnf("plex set media access failed for %s: %v", username, err)
	}
}

func plexFinalizeSession(w http.ResponseWriter, mediaUUID, username string, authorized bool) (bool, error) {
	if authorized {
		return finalizeAuthorizedLogin(w, mediaUUID, username)
	}
	if SetTempSessionCookie != nil {
		if err := SetTempSessionCookie(w, mediaUUID, username); err != nil && Warnf != nil {
			Warnf("plex temp session cookie failed: %v", err)
		}
	}
	return false, nil
}

const plexWaitingPageHTML = `<!doctype html><title>Plex: Waiting…</title><body style="font-family:system-ui;padding:2rem"><h1>Waiting for Plex approval…</h1></body>`

func plexWaitingPage() *HTTPResult {
	hdr := http.Header{}
	hdr.Set(plexHeaderContentType, "text/html; charset=utf-8")
	return &HTTPResult{
		Status: http.StatusOK,
		Header: hdr,
		Body:   []byte(plexWaitingPageHTML),
	}
}

func plexRenderWaitingPage(w http.ResponseWriter) {
	w.Header().Set(plexHeaderContentType, "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(plexWaitingPageHTML)); err != nil {
		log.Printf("WARN: plex waiting page write failed: %v", err)
	}
}

func plexSanitizeProto(r *http.Request) string {
	proto := firstForwardHeader(r.Header.Get("X-Forwarded-Proto"))
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != "http" && proto != "https" {
		if r.TLS != nil {
			return "https"
		}
		return "http"
	}
	return proto
}

func plexSanitizeHost(r *http.Request) string {
	host := firstForwardHeader(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "<>\"'\\/%") {
		return r.Host
	}
	if u, err := url.Parse("http://" + host); err == nil && u.Host == host && u.Path == "" {
		return host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if u, err2 := url.Parse("http://" + h); err2 == nil && u.Host == h && u.Path == "" {
			return host
		}
	}
	return r.Host
}

func firstForwardHeader(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	return strings.TrimSpace(parts[0])
}

// CompleteOutcome provides a structured result (no cookie writes).
func (PlexProvider) CompleteOutcome(_ context.Context, r *http.Request) (AuthOutcome, *HTTPResult, error) {
	data, err := plexResolveAuthData(r, 60*time.Second)
	if err != nil {
		if errors.Is(err, errPlexPinNotReady) {
			return AuthOutcome{}, plexWaitingPage(), nil
		}
		return AuthOutcome{}, nil, err
	}

	return AuthOutcome{
		Provider:    "plex",
		Username:    data.username,
		Email:       data.email,
		MediaUUID:   data.mediaUUID,
		SealedToken: data.sealedToken,
		Authorized:  data.authorized,
	}, nil, nil
}

// StartWeb: create PIN → return Plex UI URL
func (PlexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	clientID := randClientID()
	pin, err := plexCreatePin(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "plex pin request failed"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "plex_pin",
		// Store pin id, code, and the clientID used to create the pin
		Value: fmt.Sprintf("%d:%s:%s", pin.ID, pin.Code, clientID),
		// Use a broader path so both /auth/forward and /auth/poll can read the cookie
		Path:     "/auth",
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Determine external scheme/host correctly (supports reverse proxies)
	proto := plexSanitizeProto(r)
	host := plexSanitizeHost(r)
	fwd := fmt.Sprintf("%s://%s/auth/forward", strings.ToLower(proto), host)
	url := fmt.Sprintf("https://app.plex.tv/auth#?clientID=%s&code=%s&forwardUrl=%s&context[device][product]=AuthPortal&context[device][version]=2.0.0&context[device][platform]=Web&context[device][device]=Web", clientID, pin.Code, url.QueryEscape(fwd))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": "plex",
		"url":      url,
	})
}

func (PlexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	data, err := plexResolveAuthData(r, 60*time.Second)
	if err != nil {
		if errors.Is(err, errPlexPinNotReady) {
			plexRenderWaitingPage(w)
			return
		}
		http.Error(w, "plex authentication failed", http.StatusBadGateway)
		return
	}

	plexUpsertUserRecord(data)

	requiresMFA, err := plexFinalizeSession(w, data.mediaUUID, data.username, data.authorized)
	if err != nil {
		http.Error(w, "Login finalization failed", http.StatusInternalServerError)
		return
	}

	redirect := "/home"
	message := "Signed in - you can close this window."
	if requiresMFA {
		redirect = "/mfa/challenge"
		message = "Continue in the main window to finish multi-factor authentication."
	}
	WriteAuthCompletePage(w, AuthCompletePageOptions{
		Message:     message,
		Provider:    "plex-auth",
		Redirect:    redirect,
		RequiresMFA: requiresMFA,
	})
}

// PlexPoll provides a JSON polling endpoint to complete the PIN flow when
// the Plex app does not navigate to forwardUrl reliably.
// It mirrors Forward but returns JSON instead of HTML and uses a short poll.
func PlexPoll(w http.ResponseWriter, r *http.Request) {
	data, err := plexResolveAuthData(r, 2*time.Second)
	if err != nil {
		waitingResp := map[string]any{"ok": false, "waiting": true}
		if errors.Is(err, errPlexPinNotReady) {
			writeJSON(w, http.StatusOK, waitingResp)
			return
		}
		waitingResp["error"] = err.Error()
		writeJSON(w, http.StatusOK, waitingResp)
		return
	}

	plexUpsertUserRecord(data)
	requiresMFA, err := plexFinalizeSession(w, data.mediaUUID, data.username, data.authorized)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "login finalization failed"})
		return
	}

	if Debugf != nil {
		Debugf("plex poll success: user=%s authorized=%t", data.username, data.authorized)
	}
	redirect := "/home"
	if requiresMFA {
		redirect = "/mfa/challenge"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": redirect, "mfa": requiresMFA})
}

func (PlexProvider) IsAuthorized(uuid, _ string) (bool, error) {
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

	userToken := strings.TrimSpace(u.MediaToken)
	if userToken == "" {
		return false, nil
	}

	authorized := plexTokenAuthorized(userToken)
	if authorized {
		plexSetUserMediaAccess(u.Username, true)
		return true, nil
	}
	return false, nil
}
