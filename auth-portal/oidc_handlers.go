package main

import (
	"encoding/json"
	"net/http"
	"strings"
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
