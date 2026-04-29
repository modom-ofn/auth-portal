package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
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

const (
	oidcContentTypeJSON    = "application/json"
	oidcHeaderContent      = "Content-Type"
	oidcHeaderCache        = "Cache-Control"
	oidcHeaderPragma       = "Pragma"
	oidcHeaderWWWAuth      = "WWW-Authenticate"
	oidcHeaderAllowOrigin  = "Access-Control-Allow-Origin"
	oidcHeaderAllowMethods = "Access-Control-Allow-Methods"
	oidcHeaderAllowHeaders = "Access-Control-Allow-Headers"
	oidcHeaderMaxAge       = "Access-Control-Max-Age"
	oidcHeaderVary         = "Vary"
	oidcCacheNoStore       = "no-store"
	oidcCacheNoPragma      = "no-cache"

	errUserNotFound          = "user not found"
	errCodeVerifierMismatch  = "code_verifier mismatch"
	errTokenIssuanceFailed   = "token issuance failed"
	errRedirectNotRegistered = "redirect_uri is not registered for this client"
	errSessionRequired       = "session required"
	errInvalidForm           = "invalid form"
	errClientMismatch        = "client mismatch"

	oidcErrCodeInvalidRequest      = "invalid_request"
	oidcErrCodeAccessDenied        = "access_denied"
	oidcErrCodeServerError         = "server_error"
	oidcErrCodeInvalidGrant        = "invalid_grant"
	oidcErrCodeInvalidClient       = "invalid_client"
	oidcErrCodeUnsupportedGrant    = "unsupported_grant_type"
	oidcErrCodeUnauthorizedClient  = "unauthorized_client"
	oidcErrDescClientLookupFailed  = "client lookup failed"
	oidcErrDescGrantTypeRequired   = "grant_type required"
	oidcErrDescCodeRedirectMissing = "code and redirect_uri required"
	oidcErrDescRedirectMismatch    = "redirect_uri mismatch"
	oidcErrDescCodeInvalidExpired  = "authorization code invalid or expired"
	oidcErrDescCodeVerifierNeeded  = "code_verifier required"
	oidcErrDescRefreshTokenNeeded  = "refresh_token required"
	oidcErrDescRefreshInvalid      = "refresh token invalid or expired"
	oidcErrDescInvalidRedirectURI  = "invalid redirect_uri"
)

func oidcDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	applyOIDCDiscoveryCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	issuer := oidcIssuer()
	base := strings.TrimRight(issuer, "/")
	scopesSupported := supportedOIDCScopes()

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
		Issuer:                 issuer,
		AuthorizationEndpoint:  base + "/oidc/authorize",
		TokenEndpoint:          base + "/oidc/token",
		UserinfoEndpoint:       base + "/oidc/userinfo",
		JWKSURI:                base + "/oidc/jwks.json",
		ScopesSupported:        scopesSupported,
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

	w.Header().Set(oidcHeaderContent, oidcContentTypeJSON)
	_ = json.NewEncoder(w).Encode(resp)
}

func applyOIDCDiscoveryCORS(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return
	}
	allowedOrigin := allowedOIDCDiscoveryCORSOrigin(r.Context(), origin)
	if allowedOrigin == "" {
		return
	}
	w.Header().Set(oidcHeaderAllowOrigin, allowedOrigin)
	w.Header().Set(oidcHeaderAllowMethods, "GET, OPTIONS")
	w.Header().Set(oidcHeaderAllowHeaders, "Accept, Content-Type")
	w.Header().Set(oidcHeaderMaxAge, "3600")
	w.Header().Add(oidcHeaderVary, "Origin")
}

func allowedOIDCDiscoveryCORSOrigin(ctx context.Context, origin string) string {
	normalized := normalizedCORSOrigin(origin)
	if normalized == "" {
		return ""
	}
	if oidcDiscoveryOriginRegistered(ctx, normalized) {
		return normalized
	}
	return "*"
}

func oidcDiscoveryOriginRegistered(ctx context.Context, origin string) bool {
	if oauthService.DB == nil {
		return false
	}
	clients, err := oauthService.ListClients(ctx)
	if err != nil {
		log.Printf("oidc discovery: oauth client lookup failed for CORS origin %q: %v", origin, err)
		return false
	}
	for _, client := range clients {
		for _, redirectURI := range client.RedirectURIs {
			if redirectURIOrigin(redirectURI) == origin {
				return true
			}
		}
	}
	return false
}

func redirectURIOrigin(raw string) string {
	normalized := normalizeRedirectValue(raw)
	if normalized == "" {
		return ""
	}
	u, err := url.Parse(normalized)
	if err != nil || !u.IsAbs() {
		return ""
	}
	return normalizedURLOrigin(u)
}

func normalizedCORSOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return normalizedURLOrigin(u)
}

func normalizedURLOrigin(u *url.URL) string {
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Host))
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func oidcJWKSHandler(w http.ResponseWriter, _ *http.Request) {
	data := oidcJWKS()
	w.Header().Set(oidcHeaderContent, oidcContentTypeJSON)
	if _, err := w.Write(data); err != nil {
		log.Printf("oidc jwks: write failed: %v", err)
	}
}

func oidcAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	reqCtx, err := parseAuthorizeRequest(r)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, err.Error())
		return
	}

	client, redirectURI, scopes, err := prepareAuthorizeClient(r.Context(), reqCtx)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, err.Error())
		return
	}

	if err := validateCodeChallengeMethod(reqCtx.CodeChallenge, &reqCtx.CodeMethod); err != nil {
		writeOIDCRedirectError(w, r, redirectURI, reqCtx.State, oidcErrCodeInvalidRequest, err.Error())
		return
	}

	uuid := uuidFrom(r.Context())
	if uuid == "" {
		http.Error(w, errSessionRequired, http.StatusUnauthorized)
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, reqCtx.State, oidcErrCodeAccessDenied, errUserNotFound)
		return
	}

	requireConsent := shouldRequireConsent(r.Context(), user, client, scopes, reqCtx.PromptConsent)

	if requireConsent {
		if reqCtx.PromptNone {
			writeOIDCRedirectError(w, r, redirectURI, reqCtx.State, "consent_required", "user interaction required")
			return
		}
		renderConsentPage(w, consentTemplateData{
			ClientDisplay:       clientDisplayName(client),
			ClientID:            client.ClientID,
			RedirectURI:         redirectURI,
			State:               reqCtx.State,
			Scope:               strings.Join(scopes, " "),
			Scopes:              scopeDisplayList(scopes),
			IncludeOffline:      containsScope(scopes, "offline_access"),
			CodeChallenge:       reqCtx.CodeChallenge,
			CodeChallengeMethod: reqCtx.CodeMethod,
			Prompt:              reqCtx.PromptRaw,
			Nonce:               reqCtx.Nonce,
		})
		return
	}

	finishAuthorizeFlow(w, r, authorizeFlowInput{
		User:          user,
		Client:        client,
		RedirectURI:   redirectURI,
		State:         reqCtx.State,
		Scopes:        scopes,
		CodeChallenge: reqCtx.CodeChallenge,
		CodeMethod:    reqCtx.CodeMethod,
		Nonce:         reqCtx.Nonce,
	})
}

type authorizeRequest struct {
	ResponseType  string
	ClientID      string
	RedirectURI   string
	State         string
	Nonce         string
	CodeChallenge string
	CodeMethod    string
	Scopes        []string
	PromptRaw     string
	PromptNone    bool
	PromptConsent bool
}

func parseAuthorizeRequest(r *http.Request) (authorizeRequest, error) {
	query := r.URL.Query()
	respType := strings.TrimSpace(query.Get("response_type"))
	if respType != "code" {
		return authorizeRequest{}, errors.New("only response_type=code is supported")
	}
	clientID := strings.TrimSpace(query.Get("client_id"))
	if clientID == "" {
		return authorizeRequest{}, errors.New("client_id required")
	}
	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	if redirectURI == "" {
		return authorizeRequest{}, errors.New("redirect_uri required")
	}

	promptRaw := strings.TrimSpace(query.Get("prompt"))
	promptNone, promptConsent := parsePrompt(promptRaw)

	scopes := parseScopes(query.Get("scope"))

	return authorizeRequest{
		ResponseType:  respType,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         query.Get("state"),
		Nonce:         strings.TrimSpace(query.Get("nonce")),
		CodeChallenge: strings.TrimSpace(query.Get("code_challenge")),
		CodeMethod:    strings.TrimSpace(query.Get("code_challenge_method")),
		Scopes:        scopes,
		PromptRaw:     promptRaw,
		PromptNone:    promptNone,
		PromptConsent: promptConsent,
	}, nil
}

func parsePrompt(promptRaw string) (promptNone, promptConsent bool) {
	for _, value := range strings.Fields(promptRaw) {
		switch strings.ToLower(value) {
		case "none":
			promptNone = true
		case "consent":
			promptConsent = true
		}
	}
	return
}

func parseScopes(scopeRaw string) []string {
	scopeRaw = strings.TrimSpace(scopeRaw)
	if scopeRaw == "" {
		scopeRaw = "openid"
	}
	scopes := strings.Fields(scopeRaw)
	if !containsScope(scopes, "openid") {
		scopes = append(scopes, "openid")
	}
	return scopes
}

func prepareAuthorizeClient(ctx context.Context, req authorizeRequest) (oauth.Client, string, []string, error) {
	client, err := oauthService.Client(ctx, req.ClientID)
	if err != nil {
		return oauth.Client{}, "", nil, errors.New("client not registered")
	}
	redirectURI, err := validateRegisteredRedirectURI(client, req.RedirectURI)
	if err != nil {
		return oauth.Client{}, "", nil, err
	}
	scopes, err := enforceClientScopePolicy(req.Scopes, client)
	if err != nil {
		return oauth.Client{}, "", nil, err
	}
	scopes, err = enforceUserScopeEntitlements(ctx, scopes)
	if err != nil {
		return oauth.Client{}, "", nil, err
	}
	return client, redirectURI, scopes, nil
}

func validateCodeChallengeMethod(codeChallenge string, codeMethod *string) error {
	if strings.TrimSpace(codeChallenge) == "" {
		return nil
	}
	if strings.TrimSpace(*codeMethod) == "" {
		*codeMethod = "plain"
	}
	switch strings.ToUpper(strings.TrimSpace(*codeMethod)) {
	case "PLAIN", "S256":
		return nil
	default:
		return errors.New("unsupported code_challenge_method")
	}
}

func shouldRequireConsent(ctx context.Context, user User, client oauth.Client, scopes []string, promptConsent bool) bool {
	if promptConsent {
		return true
	}
	hasConsent, err := oauthService.HasConsent(ctx, int64(user.ID), client.ClientID, scopes)
	if err != nil {
		log.Printf("oidc authorize: consent check failed for %s/%s: %v", user.Username, client.ClientID, err)
		return true
	}
	return !hasConsent
}

func oidcAuthorizeDecisionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, errMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, errInvalidForm, http.StatusBadRequest)
		return
	}

	decision := strings.ToLower(strings.TrimSpace(r.PostFormValue("decision")))
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	redirectURI := strings.TrimSpace(r.PostFormValue("redirect_uri"))
	state := r.PostFormValue("state")
	scopes := parseScopes(r.PostFormValue("scope"))
	codeChallenge := strings.TrimSpace(r.PostFormValue("code_challenge"))
	codeMethod := strings.TrimSpace(r.PostFormValue("code_challenge_method"))
	nonce := strings.TrimSpace(r.PostFormValue("nonce"))
	if err := validateCodeChallengeMethod(codeChallenge, &codeMethod); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
		http.Error(w, errSessionRequired, http.StatusUnauthorized)
		return
	}

	user, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, oidcErrCodeAccessDenied, errUserNotFound)
		return
	}

	scopes, err = enforceClientScopePolicy(scopes, client)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, "invalid_scope", err.Error())
		return
	}
	scopes, err = enforceUserScopeEntitlements(r.Context(), scopes)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, state, oidcErrCodeAccessDenied, err.Error())
		return
	}

	if decision == "deny" {
		writeOIDCRedirectError(w, r, redirectURI, state, oidcErrCodeAccessDenied, "user denied the request")
		return
	}

	finishAuthorizeFlow(w, r, authorizeFlowInput{
		User:          user,
		Client:        client,
		RedirectURI:   redirectURI,
		State:         state,
		Scopes:        scopes,
		CodeChallenge: codeChallenge,
		CodeMethod:    codeMethod,
		Nonce:         nonce,
	})
}

func oidcTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOIDCError(w, http.StatusMethodNotAllowed, oidcErrCodeInvalidRequest, errMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, errInvalidForm)
		return
	}

	clientID, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, oidcErrCodeInvalidClient, err.Error())
		return
	}

	client, err := oauthService.AuthenticateClient(r.Context(), clientID, clientSecret)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) || errors.Is(err, oauth.ErrClientAuthFailed) {
			writeOIDCError(w, http.StatusUnauthorized, oidcErrCodeInvalidClient, "client authentication failed")
			return
		}
		log.Printf("oidc token: client lookup failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, oidcErrCodeServerError, oidcErrDescClientLookupFailed)
		return
	}

	grantType := strings.TrimSpace(r.PostFormValue("grant_type"))
	if grantType == "" {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, oidcErrDescGrantTypeRequired)
		return
	}

	normalizedGrant := strings.ToLower(grantType)
	if !clientAllowsGrant(client, normalizedGrant) {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeUnauthorizedClient, "grant type not allowed for this client")
		return
	}

	switch normalizedGrant {
	case "authorization_code":
		handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		handleRefreshTokenGrant(w, r, client)
	default:
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeUnsupportedGrant, "grant type not supported")
	}
}

type authorizationCodeGrantInput struct {
	code         string
	redirectURI  string
	codeVerifier string
}

var errAuthorizationCodeUserNotFound = errors.New("authorization code user not found")

func parseAuthorizationCodeGrantInput(w http.ResponseWriter, r *http.Request, client oauth.Client) (authorizationCodeGrantInput, bool) {
	input := authorizationCodeGrantInput{
		code:         strings.TrimSpace(r.PostFormValue("code")),
		redirectURI:  strings.TrimSpace(r.PostFormValue("redirect_uri")),
		codeVerifier: strings.TrimSpace(r.PostFormValue("code_verifier")),
	}

	if input.code == "" || input.redirectURI == "" {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, oidcErrDescCodeRedirectMissing)
		return authorizationCodeGrantInput{}, false
	}
	if !clientAllowsRedirect(client, input.redirectURI) {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, oidcErrDescRedirectMismatch)
		return authorizationCodeGrantInput{}, false
	}
	return input, true
}

func consumeAndValidateAuthorizationCode(
	w http.ResponseWriter,
	ctx context.Context,
	client oauth.Client,
	input authorizationCodeGrantInput,
) (oauth.AuthCode, bool) {
	authCode, err := oauthService.ConsumeAuthCode(ctx, input.code)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, oidcErrDescCodeInvalidExpired)
		return oauth.AuthCode{}, false
	}
	if authCode.ClientID != client.ClientID {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, errClientMismatch)
		return oauth.AuthCode{}, false
	}
	if authCode.RedirectURI != input.redirectURI {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, oidcErrDescRedirectMismatch)
		return oauth.AuthCode{}, false
	}
	if authCode.CodeChallenge.Valid {
		if input.codeVerifier == "" {
			writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, oidcErrDescCodeVerifierNeeded)
			return oauth.AuthCode{}, false
		}
		if !verifyCodeChallenge(authCode.CodeMethod.String, authCode.CodeChallenge.String, input.codeVerifier) {
			writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, errCodeVerifierMismatch)
			return oauth.AuthCode{}, false
		}
	}
	return authCode, true
}

func issueAuthCodeGrantTokens(
	ctx context.Context,
	client oauth.Client,
	authCode oauth.AuthCode,
) (oauth.AccessToken, string, time.Time, string, error) {
	user, err := userByID(int(authCode.UserID))
	if err != nil {
		return oauth.AccessToken{}, "", time.Time{}, "", errAuthorizationCodeUserNotFound
	}
	if _, err := enforceUserScopeEntitlementsForIdentity(strings.TrimSpace(user.MediaUUID.String), strings.TrimSpace(user.Username), authCode.Scopes); err != nil {
		return oauth.AccessToken{}, "", time.Time{}, "", err
	}

	access, err := oauthService.CreateAccessToken(ctx, client.ClientID, authCode.UserID, authCode.Scopes)
	if err != nil {
		log.Printf("oidc token: access token create failed: %v", err)
		return oauth.AccessToken{}, "", time.Time{}, "", err
	}

	refresh := ""
	refreshExpiry := time.Time{}
	if containsScope(authCode.Scopes, "offline_access") {
		refresh, refreshExpiry, err = oauthService.CreateRefreshToken(ctx, access.TokenID, client.ClientID, authCode.UserID, authCode.Scopes)
		if err != nil {
			log.Printf("oidc token: refresh token create failed: %v", err)
			return oauth.AccessToken{}, "", time.Time{}, "", err
		}
	}

	idToken, err := mintIDToken(client.ClientID, user, access.ExpiresAt, authCode.Nonce.String)
	if err != nil {
		log.Printf("oidc token: id token mint failed: %v", err)
		return oauth.AccessToken{}, "", time.Time{}, "", err
	}

	return access, refresh, refreshExpiry, idToken, nil
}

func writeOIDCTokenSuccessResponse(w http.ResponseWriter, access oauth.AccessToken, scopes []string, idToken, refresh string, refreshExpiry time.Time) {
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
		"scope":        strings.Join(scopes, " "),
	}
	if refresh != "" {
		refreshIn := int(refreshExpiry.Sub(now).Seconds())
		if refreshIn < 0 {
			refreshIn = 0
		}
		response["refresh_token"] = refresh
		response["refresh_expires_in"] = refreshIn
	}

	w.Header().Set(oidcHeaderContent, oidcContentTypeJSON)
	w.Header().Set(oidcHeaderCache, oidcCacheNoStore)
	w.Header().Set(oidcHeaderPragma, oidcCacheNoPragma)
	_ = json.NewEncoder(w).Encode(response)
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client oauth.Client) {
	input, ok := parseAuthorizationCodeGrantInput(w, r, client)
	if !ok {
		return
	}

	authCode, ok := consumeAndValidateAuthorizationCode(w, r.Context(), client, input)
	if !ok {
		return
	}

	access, refresh, refreshExpiry, idToken, err := issueAuthCodeGrantTokens(r.Context(), client, authCode)
	if err != nil {
		if errors.Is(err, errAuthorizationCodeUserNotFound) {
			writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, errUserNotFound)
			return
		}
		writeOIDCError(w, http.StatusInternalServerError, oidcErrCodeServerError, errTokenIssuanceFailed)
		return
	}

	writeOIDCTokenSuccessResponse(w, access, authCode.Scopes, idToken, refresh, refreshExpiry)
}
func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client oauth.Client) {
	refreshToken := strings.TrimSpace(r.PostFormValue("refresh_token"))
	if refreshToken == "" {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, oidcErrDescRefreshTokenNeeded)
		return
	}

	access, newRefresh, refreshExpiry, err := oauthService.UseRefreshToken(r.Context(), refreshToken, client.ClientID)
	if err != nil {
		if errors.Is(err, oauth.ErrTokenNotFound) || errors.Is(err, oauth.ErrTokenExpired) || errors.Is(err, oauth.ErrTokenRevoked) {
			writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, oidcErrDescRefreshInvalid)
			return
		}
		log.Printf("oidc token: refresh flow failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, oidcErrCodeServerError, errTokenIssuanceFailed)
		return
	}

	if access.ClientID != client.ClientID {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, errClientMismatch)
		return
	}

	user, err := userByID(int(access.UserID))
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, errUserNotFound)
		return
	}
	updatedScopes, err := enforceUserScopeEntitlementsForIdentity(strings.TrimSpace(user.MediaUUID.String), strings.TrimSpace(user.Username), access.Scopes)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidGrant, err.Error())
		return
	}
	access.Scopes = updatedScopes

	idToken, err := mintIDToken(client.ClientID, user, access.ExpiresAt, "")
	if err != nil {
		log.Printf("oidc token: id token mint failed: %v", err)
		writeOIDCError(w, http.StatusInternalServerError, oidcErrCodeServerError, errTokenIssuanceFailed)
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

	w.Header().Set(oidcHeaderContent, oidcContentTypeJSON)
	w.Header().Set(oidcHeaderCache, oidcCacheNoStore)
	w.Header().Set(oidcHeaderPragma, oidcCacheNoPragma)
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
		w.Header().Set(oidcHeaderWWWAuth, `Bearer error="invalid_token", error_description="token invalid or expired"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := userByID(int(access.UserID))
	if err != nil {
		w.Header().Set(oidcHeaderWWWAuth, `Bearer error="invalid_token", error_description="user not found"`)
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

	w.Header().Set(oidcHeaderContent, oidcContentTypeJSON)
	_ = json.NewEncoder(w).Encode(payload)
}

func verifyCodeChallenge(method, storedChallenge, verifier string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])
		return subtleConstantTimeCompare(expected, storedChallenge) == 1
	case "PLAIN", "":
		return subtleConstantTimeCompare(verifier, storedChallenge) == 1
	default:
		return false
	}
}

func writeOIDCError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set(oidcHeaderContent, oidcContentTypeJSON)
	w.Header().Set(oidcHeaderCache, oidcCacheNoStore)
	w.Header().Set(oidcHeaderPragma, oidcCacheNoPragma)
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
	if u.IsAbs() {
		scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
		if (scheme != "https" && scheme != "http") || strings.TrimSpace(u.Hostname()) == "" {
			writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, oidcErrDescInvalidRedirectURI)
			return
		}
	} else if !(strings.HasPrefix(redirectURI, "/") && (len(redirectURI) == 1 || (redirectURI[1] != '/' && redirectURI[1] != '\\'))) {
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, oidcErrDescInvalidRedirectURI)
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
		return "", errors.New(errRedirectNotRegistered)
	}

	parsed, err := url.Parse(normalized)
	if err != nil || parsed.String() == "" {
		return "", errors.New("invalid redirect_uri")
	}
	if parsed.Fragment != "" {
		return "", errors.New("redirect_uri must not include a fragment component")
	}
	if err := validateRedirectHost(parsed, normalized, client); err != nil {
		return "", err
	}

	for _, reg := range client.RedirectURIs {
		if normalizeRedirectValue(reg) == normalized {
			return normalized, nil
		}
	}

	return "", errors.New(errRedirectNotRegistered)
}

func validateRedirectHost(parsed *url.URL, normalized string, client oauth.Client) error {
	if parsed.IsAbs() {
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "http" {
			return errors.New("redirect_uri must use http or https scheme")
		}
		if parsed.Hostname() == "" {
			return errors.New("redirect_uri must include a hostname")
		}
		if !isTrustedRedirectHost(parsed.Hostname(), client) {
			return errors.New("redirect_uri hostname is not trusted")
		}
		return nil
	}
	if !(strings.HasPrefix(normalized, "/") && (len(normalized) == 1 || (normalized[1] != '/' && normalized[1] != '\\'))) {
		return errors.New("redirect_uri must start with a single / and not be followed by / or \\")
	}
	return nil
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
		if description, err := permissionDescription(scope); err == nil && description != "" {
			return description
		}
		return "Requested scope: " + scope
	}
}

type authorizeFlowInput struct {
	User          User
	Client        oauth.Client
	RedirectURI   string
	State         string
	Scopes        []string
	CodeChallenge string
	CodeMethod    string
	Nonce         string
}

func finishAuthorizeFlow(w http.ResponseWriter, r *http.Request, input authorizeFlowInput) {
	user := input.User
	client := input.Client
	redirectURI := input.RedirectURI
	validatedRedirect, err := validateRegisteredRedirectURI(client, redirectURI)
	if err != nil {
		log.Printf("oidc authorize: refusing redirect for %s to %s: %v", client.ClientID, redirectURI, err)
		writeOIDCError(w, http.StatusBadRequest, oidcErrCodeInvalidRequest, errRedirectNotRegistered)
		return
	}
	redirectURI = validatedRedirect

	if err := oauthService.RecordConsent(r.Context(), int64(user.ID), client.ClientID, input.Scopes); err != nil {
		log.Printf("oidc authorize: record consent failed for %s/%s: %v", user.Username, client.ClientID, err)
	}

	authCode, err := oauthService.CreateAuthCode(r.Context(), client.ClientID, int64(user.ID), oauth.AuthCodeOptions{
		RedirectURI:   redirectURI,
		Scopes:        input.Scopes,
		CodeChallenge: input.CodeChallenge,
		CodeMethod:    input.CodeMethod,
		Nonce:         input.Nonce,
	})
	if err != nil {
		log.Printf("oidc authorize: create code failed: %v", err)
		writeOIDCRedirectError(w, r, redirectURI, input.State, oidcErrCodeServerError, "authorization failed")
		return
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		writeOIDCRedirectError(w, r, redirectURI, input.State, oidcErrCodeInvalidRequest, oidcErrDescInvalidRedirectURI)
		return
	}
	params := redirect.Query()
	params.Set("code", authCode.Code)
	if input.State != "" {
		params.Set("state", input.State)
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

func supportedOIDCScopes() []string {
	base := []string{"openid", "profile", "email", "offline_access"}
	permissions, err := listPermissionNames()
	if err != nil {
		return base
	}
	return normalizeDistinctStrings(append(base, permissions...))
}

func isStandardOIDCScope(scope string) bool {
	switch strings.TrimSpace(scope) {
	case "openid", "profile", "email", "offline_access":
		return true
	default:
		return false
	}
}

func permissionDescription(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	var description sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT description FROM permissions WHERE name = $1`, normalizeRBACName(name)).Scan(&description); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(description.String), nil
}

func enforceUserScopeEntitlements(ctx context.Context, scopes []string) ([]string, error) {
	username := usernameFrom(ctx)
	uuid := uuidFrom(ctx)
	if username == "" && uuid == "" {
		return nil, errors.New("session required")
	}
	return enforceUserScopeEntitlementsForIdentity(uuid, username, scopes)
}

func enforceUserScopeEntitlementsForIdentity(uuid, username string, scopes []string) ([]string, error) {
	grantedPermissions, err := userPermissions(uuid, username)
	if err != nil {
		return nil, fmt.Errorf("permission lookup failed")
	}
	granted := make(map[string]struct{}, len(grantedPermissions))
	for _, permission := range grantedPermissions {
		granted[normalizeRBACName(permission)] = struct{}{}
	}

	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if isStandardOIDCScope(scope) {
			out = append(out, scope)
			continue
		}
		if _, ok := granted[normalizeRBACName(scope)]; !ok {
			return nil, fmt.Errorf("scope %q is not granted to this user", scope)
		}
		out = append(out, normalizeRBACName(scope))
	}
	if len(out) == 0 {
		return []string{"openid"}, nil
	}
	return out, nil
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
