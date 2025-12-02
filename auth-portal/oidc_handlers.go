package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"auth-portal/oauth"
)

func oidcDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	issuer := oidcIssuer()
	base := strings.TrimRight(issuer, "/")

	type response struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
		JWKSURI                           string   `json:"jwks_uri"`
		ScopesSupported                   []string `json:"scopes_supported"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		GrantTypesSupported               []string `json:"grant_types_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
		SubjectTypesSupported             []string `json:"subject_types_supported"`
		ClaimsSupported                   []string `json:"claims_supported"`
		ClaimTypesSupported               []string `json:"claim_types_supported"`
	}

	resp := response{
		Issuer:                issuer,
		AuthorizationEndpoint: base + "/oidc/authorize",
		TokenEndpoint:         base + "/oidc/token",
		UserinfoEndpoint:      base + "/oidc/userinfo",
		JWKSURI:               base + "/oidc/jwks.json",
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported: []string{
			"S256",
			"plain",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		SubjectTypesSupported:            []string{"public"},
		ClaimsSupported: []string{
			"sub",
			"name",
			"preferred_username",
			"email",
			"email_verified",
		},
		ClaimTypesSupported: []string{"normal"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func oidcJWKSHandler(w http.ResponseWriter, r *http.Request) {
	data := oidcJWKS()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func oidcAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	responseType := strings.TrimSpace(query.Get("response_type"))
	if responseType != "code" {
		writeOIDCError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	clientID := strings.TrimSpace(query.Get("client_id"))
	if clientID == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "client_id required")
		return
	}

	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	if redirectURI == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
		return
	}

	state := query.Get("state")
	nonce := strings.TrimSpace(query.Get("nonce"))
	promptRaw := strings.TrimSpace(query.Get("prompt"))
	promptValues := strings.Fields(promptRaw)
	promptNone := false
	promptConsent := false
	for _, value := range promptValues {
		switch strings.ToLower(value) {
		case "none":
			promptNone = true
		case "consent":
			promptConsent = true
		}
	}

	scopeRaw := strings.TrimSpace(query.Get("scope"))
	if scopeRaw == "" {
		scopeRaw = "openid"
	}
	scopes := strings.Fields(scopeRaw)
	if !containsScope(scopes, "openid") {
		scopes = append(scopes, "openid")
	}

	client, err := oauthService.Client(r.Context(), clientID)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "unauthorized_client", "client not registered")
		return
	}
	redirectURI, err = validateRegisteredRedirectURI(client, redirectURI)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	scopes, err = enforceClientScopePolicy(scopes, client)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, "invalid_scope", err.Error())
		return
	}

	codeChallenge := strings.TrimSpace(query.Get("code_challenge"))
	codeMethod := strings.TrimSpace(query.Get("code_challenge_method"))
	if codeChallenge != "" {
		if codeMethod == "" {
			codeMethod = "plain"
		}
		switch strings.ToUpper(codeMethod) {
		case "PLAIN", "S256":
			// ok
		default:
			writeOIDCRedirectError(w, r, redirectURI, state, "invalid_request", "unsupported code_challenge_method")
			return
		}
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		http.Error(w, "session required", http.StatusUnauthorized)
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, "access_denied", "user not found")
		return
	}

	requireConsent := promptConsent
	if !requireConsent {
		hasConsent, err := oauthService.HasConsent(r.Context(), int64(user.ID), client.ClientID, scopes)
		if err != nil {
			log.Printf("oidc authorize: consent check failed for %s/%s: %v", user.Username, client.ClientID, err)
			writeOIDCRedirectError(w, r, redirectURI, state, "server_error", "authorization failed")
			return
		}
		requireConsent = !hasConsent
	}

	if requireConsent {
		if promptNone {
			writeOIDCRedirectError(w, r, redirectURI, state, "consent_required", "user interaction required")
			return
		}
		renderConsentPage(w, consentTemplateData{
			ClientDisplay:       clientDisplayName(client),
			ClientID:            client.ClientID,
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               strings.Join(scopes, " "),
			Scopes:              scopeDisplayList(scopes),
			IncludeOffline:      containsScope(scopes, "offline_access"),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeMethod,
			Prompt:              promptRaw,
			Nonce:               nonce,
		})
		return
	}

	finishAuthorizeFlow(w, r, user, client, redirectURI, state, scopes, codeChallenge, codeMethod, nonce)
}

func oidcAuthorizeDecisionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	decision := strings.ToLower(strings.TrimSpace(r.PostFormValue("decision")))
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	redirectURI := strings.TrimSpace(r.PostFormValue("redirect_uri"))
	state := r.PostFormValue("state")
	scopeRaw := strings.TrimSpace(r.PostFormValue("scope"))
	if scopeRaw == "" {
		scopeRaw = "openid"
	}
	scopes := strings.Fields(scopeRaw)
	if !containsScope(scopes, "openid") {
		scopes = append(scopes, "openid")
	}
	codeChallenge := strings.TrimSpace(r.PostFormValue("code_challenge"))
	codeMethod := strings.TrimSpace(r.PostFormValue("code_challenge_method"))
	nonce := strings.TrimSpace(r.PostFormValue("nonce"))
	if codeChallenge != "" {
		if codeMethod == "" {
			codeMethod = "plain"
		}
		switch strings.ToUpper(codeMethod) {
		case "PLAIN", "S256":
		default:
			http.Error(w, "unsupported code method", http.StatusBadRequest)
			return
		}
	}

	if decision != "allow" && decision != "deny" {
		http.Error(w, "invalid decision", http.StatusBadRequest)
		return
	}
	if clientID == "" || redirectURI == "" {
		http.Error(w, "client and redirect required", http.StatusBadRequest)
		return
	}

	client, err := oauthService.Client(r.Context(), clientID)
	if err != nil {
		http.Error(w, "client not registered", http.StatusBadRequest)
		return
	}
	redirectURI, err = validateRegisteredRedirectURI(client, redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		http.Error(w, "session required", http.StatusUnauthorized)
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, "access_denied", "user not found")
		return
	}

	scopes, err = enforceClientScopePolicy(scopes, client)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, "invalid_scope", err.Error())
		return
	}

	if decision == "deny" {
		writeOIDCRedirectError(w, r, redirectURI, state, "access_denied", "user denied the request")
		return
	}

	finishAuthorizeFlow(w, r, user, client, redirectURI, state, scopes, codeChallenge, codeMethod, nonce)
}

func oidcTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOIDCError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}

	clientID, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	client, err := oauthService.AuthenticateClient(r.Context(), clientID, clientSecret)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) || errors.Is(err, oauth.ErrClientAuthFailed) {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
		log.Printf("oidc token: client lookup failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "client lookup failed")
		return
	}

	grantType := strings.TrimSpace(r.PostFormValue("grant_type"))
	if grantType == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "grant_type required")
		return
	}

	normalizedGrant := strings.ToLower(grantType)
	if !clientAllowsGrant(client, normalizedGrant) {
		writeOIDCError(w, http.StatusBadRequest, "unauthorized_client", "grant type not allowed for this client")
		return
	}

	switch normalizedGrant {
	case "authorization_code":
		handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		handleRefreshTokenGrant(w, r, client)
	default:
		writeOIDCError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client oauth.Client) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	redirectURI := strings.TrimSpace(r.PostFormValue("redirect_uri"))
	codeVerifier := strings.TrimSpace(r.PostFormValue("code_verifier"))

	if code == "" || redirectURI == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri required")
		return
	}
	if !clientAllowsRedirect(client, redirectURI) {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	authCode, err := oauthService.ConsumeAuthCode(r.Context(), code)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "authorization code invalid or expired")
		return
	}
	if authCode.ClientID != client.ClientID {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	if authCode.RedirectURI != redirectURI {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if authCode.CodeChallenge.Valid {
		if codeVerifier == "" {
			writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "code_verifier required")
			return
		}
		switch strings.ToUpper(authCode.CodeMethod.String) {
		case "S256":
			hash := sha256.Sum256([]byte(codeVerifier))
			expected := base64.RawURLEncoding.EncodeToString(hash[:])
			if subtleConstantTimeCompare(expected, authCode.CodeChallenge.String) != 1 {
				writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "code_verifier mismatch")
				return
			}
		case "PLAIN", "":
			if subtleConstantTimeCompare(codeVerifier, authCode.CodeChallenge.String) != 1 {
				writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "code_verifier mismatch")
				return
			}
		default:
			writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "code_verifier mismatch")
			return
		}
	}

	user, err := getUserByID(int(authCode.UserID))
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "user not found")
		return
	}

	access, err := oauthService.CreateAccessToken(r.Context(), client.ClientID, authCode.UserID, authCode.Scopes)
	if err != nil {
		log.Printf("oidc token: access token create failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	var (
		refresh       string
		refreshExpiry time.Time
	)
	if containsScope(authCode.Scopes, "offline_access") {
		var err error
		refresh, refreshExpiry, err = oauthService.CreateRefreshToken(r.Context(), access.TokenID, client.ClientID, authCode.UserID, authCode.Scopes)
		if err != nil {
			log.Printf("oidc token: refresh token create failed: %v", err)
			writeOIDCError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
			return
		}
	}

	idToken, err := mintIDToken(client.ClientID, user, access.ExpiresAt, authCode.Nonce.String)
	if err != nil {
		log.Printf("oidc token: id token mint failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	now := time.Now()
	expiresIn := int(access.ExpiresAt.Sub(now).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	response := map[string]any{
		"access_token": access.TokenID,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"id_token":     idToken,
		"scope":        strings.Join(authCode.Scopes, " "),
	}
	if refresh != "" {
		refreshIn := int(refreshExpiry.Sub(now).Seconds())
		if refreshIn < 0 {
			refreshIn = 0
		}
		response["refresh_token"] = refresh
		response["refresh_expires_in"] = refreshIn
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(response)
}
func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client oauth.Client) {
	refreshToken := strings.TrimSpace(r.PostFormValue("refresh_token"))
	if refreshToken == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
		return
	}

	access, newRefresh, refreshExpiry, err := oauthService.UseRefreshToken(r.Context(), refreshToken, client.ClientID)
	if err != nil {
		if errors.Is(err, oauth.ErrTokenNotFound) || errors.Is(err, oauth.ErrTokenExpired) || errors.Is(err, oauth.ErrTokenRevoked) {
			writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "refresh token invalid or expired")
			return
		}
		log.Printf("oidc token: refresh flow failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	if access.ClientID != client.ClientID {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}

	user, err := getUserByID(int(access.UserID))
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", "user not found")
		return
	}

	idToken, err := mintIDToken(client.ClientID, user, access.ExpiresAt, "")
	if err != nil {
		log.Printf("oidc token: id token mint failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	now := time.Now()
	expiresIn := int(access.ExpiresAt.Sub(now).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	response := map[string]any{
		"access_token": access.TokenID,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"id_token":     idToken,
		"scope":        strings.Join(access.Scopes, " "),
	}
	if newRefresh != "" {
		refreshIn := int(refreshExpiry.Sub(now).Seconds())
		if refreshIn < 0 {
			refreshIn = 0
		}
		response["refresh_token"] = newRefresh
		response["refresh_expires_in"] = refreshIn
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(response)
}

func oidcUserinfoHandler(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="bearer token required"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	access, err := oauthService.AccessToken(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token invalid or expired"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := getUserByID(int(access.UserID))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="user not found"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	payload := map[string]any{
		"sub":                subjectForUser(user),
		"preferred_username": strings.TrimSpace(user.Username),
		"name":               strings.TrimSpace(user.Username),
		"email_verified":     user.Email.Valid && strings.TrimSpace(user.Email.String) != "",
	}
	if user.Email.Valid && strings.TrimSpace(user.Email.String) != "" {
		payload["email"] = strings.TrimSpace(user.Email.String)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func writeOIDCError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeOIDCRedirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redirectURI = normalizeRedirectValue(redirectURI)
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, code, description)
		return
	}
	if host := strings.TrimSpace(u.Hostname()); host != "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "unsafe redirect_uri: must be a relative URL")
		return
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

var trustedRedirectHosts = parseTrustedRedirectHosts(os.Getenv("TRUSTED_REDIRECT_HOSTS"))

func parseTrustedRedirectHosts(raw string) map[string]struct{} {
	hosts := make(map[string]struct{})
	if raw != "" {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';'
		}) {
			host := strings.ToLower(strings.TrimSpace(part))
			if host == "" {
				continue
			}
			hosts[host] = struct{}{}
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	return hosts
}

func normalizeRedirectValue(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return strings.ReplaceAll(trimmed, "\\", "/")
}

func extractHostFromURI(raw string) string {
	normalized := normalizeRedirectValue(raw)
	if normalized == "" {
		return ""
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func isTrustedRedirectHost(host string, client oauth.Client) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if len(trustedRedirectHosts) > 0 {
		_, ok := trustedRedirectHosts[host]
		return ok
	}
	for _, reg := range client.RedirectURIs {
		if h := extractHostFromURI(reg); h != "" && host == h {
			return true
		}
	}
	return false
}

func validateRegisteredRedirectURI(client oauth.Client, redirectURI string) (string, error) {
	normalized := normalizeRedirectValue(redirectURI)
	if normalized == "" {
		return "", errors.New("redirect_uri required")
	}
	if len(client.RedirectURIs) == 0 {
		return "", errors.New("redirect_uri is not registered for this client")
	}

	parsed, err := url.Parse(normalized)
	if err != nil || parsed.String() == "" {
		return "", errors.New("invalid redirect_uri")
	}
	if parsed.Fragment != "" {
		return "", errors.New("redirect_uri must not include a fragment component")
	}
	if parsed.IsAbs() {
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "http" {
			return "", errors.New("redirect_uri must use http or https scheme")
		}
		if parsed.Hostname() == "" {
			return "", errors.New("redirect_uri must include a hostname")
		}
		if !isTrustedRedirectHost(parsed.Hostname(), client) {
			return "", errors.New("redirect_uri hostname is not trusted")
		}
	} else {
		if !strings.HasPrefix(normalized, "/") {
			return "", errors.New("redirect_uri must be absolute or start with /")
		}
	}

	for _, reg := range client.RedirectURIs {
		if normalizeRedirectValue(reg) == normalized {
			return normalized, nil
		}
	}

	return "", errors.New("redirect_uri is not registered for this client")
}

func clientAllowsRedirect(client oauth.Client, redirect string) bool {
	_, err := validateRegisteredRedirectURI(client, redirect)
	return err == nil
}

func clientAllowsGrant(client oauth.Client, grant string) bool {
	grant = strings.TrimSpace(strings.ToLower(grant))
	if grant == "" {
		return false
	}
	if len(client.GrantTypes) == 0 {
		return grant == "authorization_code"
	}
	for _, allowed := range client.GrantTypes {
		if strings.TrimSpace(strings.ToLower(allowed)) == grant {
			return true
		}
	}
	return false
}

type consentTemplateData struct {
	ClientDisplay       string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	Scopes              []consentScopeDisplay
	IncludeOffline      bool
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	Nonce               string
}

type consentScopeDisplay struct {
	Name        string
	Description string
}

func renderConsentPage(w http.ResponseWriter, data consentTemplateData) {
	render(w, "oidc_consent.html", data)
}

func clientDisplayName(client oauth.Client) string {
	if name := strings.TrimSpace(client.Name); name != "" {
		return name
	}
	return client.ClientID
}

func scopeDisplayList(scopes []string) []consentScopeDisplay {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]consentScopeDisplay, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, consentScopeDisplay{
			Name:        scope,
			Description: scopeDescription(scope),
		})
	}
	return out
}

func scopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Sign in with AuthPortal and share your unique identifier."
	case "profile":
		return "Allow access to your basic profile (username and display information)."
	case "email":
		return "Allow access to your email address."
	case "offline_access":
		return "Allow the app to refresh tokens without you signing in again."
	default:
		return "Requested scope: " + scope
	}
}

func finishAuthorizeFlow(w http.ResponseWriter, r *http.Request, user User, client oauth.Client, redirectURI, state string, scopes []string, codeChallenge, codeMethod, nonce string) {
	validatedRedirect, err := validateRegisteredRedirectURI(client, redirectURI)
	if err != nil {
		log.Printf("oidc authorize: refusing redirect for %s to %s: %v", client.ClientID, redirectURI, err)
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		return
	}
	redirectURI = validatedRedirect

	if err := oauthService.RecordConsent(r.Context(), int64(user.ID), client.ClientID, scopes); err != nil {
		log.Printf("oidc authorize: record consent failed for %s/%s: %v", user.Username, client.ClientID, err)
	}

	authCode, err := oauthService.CreateAuthCode(r.Context(), client.ClientID, int64(user.ID), oauth.AuthCodeOptions{
		RedirectURI:   redirectURI,
		Scopes:        scopes,
		CodeChallenge: codeChallenge,
		CodeMethod:    codeMethod,
		Nonce:         nonce,
	})
	if err != nil {
		log.Printf("oidc authorize: create code failed: %v", err)
		writeOIDCRedirectError(w, r, redirectURI, state, "server_error", "authorization failed")
		return
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, "invalid_request", "invalid redirect_uri")
		return
	}
	params := redirect.Query()
	params.Set("code", authCode.Code)
	if state != "" {
		params.Set("state", state)
	}
	redirect.RawQuery = params.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func containsScope(scopes []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func enforceClientScopePolicy(requested []string, client oauth.Client) ([]string, error) {
	allowed := allowedScopesForClient(client)
	unique := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := allowed[scope]; !ok {
			return nil, fmt.Errorf("scope %q is not allowed for this client", scope)
		}
		if _, dup := seen[scope]; dup {
			continue
		}
		seen[scope] = struct{}{}
		unique = append(unique, scope)
	}
	if len(unique) == 0 {
		return []string{"openid"}, nil
	}
	return unique, nil
}

func allowedScopesForClient(client oauth.Client) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, scope := range client.Scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			allowed[scope] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		for _, def := range []string{"openid", "profile", "email"} {
			allowed[def] = struct{}{}
		}
	} else if _, ok := allowed["openid"]; !ok {
		allowed["openid"] = struct{}{}
	}
	return allowed
}

func extractClientCredentials(r *http.Request) (string, string, error) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "basic ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			return "", "", fmt.Errorf("invalid basic auth")
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid basic auth")
		}
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	}
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	clientSecret := strings.TrimSpace(r.PostFormValue("client_secret"))
	if clientID == "" {
		return "", "", fmt.Errorf("client credentials required")
	}
	return clientID, clientSecret, nil
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	if len(header) < 7 || !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func mintIDToken(audience string, user User, expires time.Time, nonce string) (string, error) {
	if oidcSigningKey == nil {
		return "", errors.New("signing key unavailable")
	}
	now := time.Now()
	subject := subjectForUser(user)
	claims := jwt.MapClaims{
		"iss":                oidcIssuer(),
		"sub":                subject,
		"aud":                audience,
		"exp":                expires.Unix(),
		"iat":                now.Unix(),
		"auth_time":          now.Unix(),
		"preferred_username": strings.TrimSpace(user.Username),
	}
	if user.Email.Valid && strings.TrimSpace(user.Email.String) != "" {
		email := strings.TrimSpace(user.Email.String)
		claims["email"] = email
		claims["email_verified"] = true
	}

	if n := strings.TrimSpace(nonce); n != "" {
		claims["nonce"] = n
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = oidcSigningKeyID
	signed, err := token.SignedString(oidcSigningKey)
	if err != nil {
		return "", err
	}
	return signed, nil
}

func subjectForUser(user User) string {
	if user.MediaUUID.Valid && strings.TrimSpace(user.MediaUUID.String) != "" {
		return strings.TrimSpace(user.MediaUUID.String)
	}
	return fmt.Sprintf("user-%d", user.ID)
}

func subtleConstantTimeCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
