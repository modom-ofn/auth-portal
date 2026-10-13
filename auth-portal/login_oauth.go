package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Cancellation does not require a login, but must validate the registered client
// callback before returning an OAuth error to an external application.
func oidcLoginCancelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req, err := parseLoginContinuation(r.PostForm.Get("next"))
	if err != nil {
		http.Error(w, "invalid continuation", http.StatusBadRequest)
		return
	}
	client, err := oauthService.Client(r.Context(), req.ClientID)
	if err != nil {
		http.Error(w, "client not registered", http.StatusBadRequest)
		return
	}
	callback, err := validateRegisteredRedirectURI(client, req.RedirectURI)
	if err != nil {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	dest, err := url.Parse(callback)
	if err != nil {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	q := dest.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	q.Set("error_description", "Login cancelled by user")
	q.Set("state", req.State)
	dest.RawQuery = q.Encode()
	http.SetCookie(w, &http.Cookie{Name: "plex_pin", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, map[string]any{"redirect": dest.String()})
}

func parseLoginContinuation(raw string) (authorizeRequest, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != oidcAuthorizePath || u.Fragment != "" {
		return authorizeRequest{}, errors.New("invalid continuation")
	}
	return parseAuthorizeRequest(&http.Request{URL: u})
}
