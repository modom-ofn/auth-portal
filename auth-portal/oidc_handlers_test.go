package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"auth-portal/oauth"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

const (
	sqlMockErrFmt            = "sqlmock.New: %v"
	unmetExpectationsFmt     = "unmet expectations: %v"
	unexpectedErrorFmt       = "unexpected error: %v"
	unexpectedScopesFmt      = "unexpected scopes: got %v want %v"
	unexpectedStatusFmt      = "unexpected status: got %d want %d"
	decodeResponseFmt        = "decode response: %v"
	unexpectedErrorCodeFmt   = "unexpected error code: got %q want %q"
	unexpectedDescriptionFmt = "unexpected description: got %q want %q"

	testClientID    = "client-123"
	testClientName  = "Test App"
	testCallbackURL = "https://example.com/callback"
	testTokenPath   = "/oidc/token"
	mimeFormURLEnc  = "application/x-www-form-urlencoded"
)

func TestFinishAuthorizeFlowSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf(sqlMockErrFmt, err)
	}
	defer db.Close()

	originalService := oauthService
	defer func() { oauthService = originalService }()

	oauthService = oauth.Service{DB: db}

	user := User{ID: 7, Username: "tester"}
	client := oauth.Client{
		ClientID:     testClientID,
		Name:         testClientName,
		RedirectURIs: []string{testCallbackURL},
	}
	redirectURI := testCallbackURL
	scopes := []string{"openid", "profile"}

	mock.ExpectExec("INSERT INTO oauth_consents").
		WithArgs(int64(user.ID), client.ClientID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectExec("INSERT INTO oauth_auth_codes").
		WithArgs(sqlmock.AnyArg(), client.ClientID, int64(user.ID), sqlmock.AnyArg(), redirectURI, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := httptest.NewRequest("GET", "/oidc/authorize", nil)
	rr := httptest.NewRecorder()

	finishAuthorizeFlow(rr, req, authorizeFlowInput{
		User:          user,
		Client:        client,
		RedirectURI:   redirectURI,
		State:         "xyz",
		Scopes:        scopes,
		CodeChallenge: "",
		CodeMethod:    "",
		Nonce:         "nonce-123",
	})

	resp := rr.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("expected redirect, got status %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatalf("expected Location header")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf(unmetExpectationsFmt, err)
	}
}

func TestScopeDisplayList(t *testing.T) {
	scopes := []string{"openid", "profile", "profile", "email"}
	display := scopeDisplayList(scopes)
	if len(display) != 3 {
		t.Fatalf("expected 3 unique scopes, got %d", len(display))
	}
	expected := map[string]string{
		"openid":  "Sign in with AuthPortal and share your unique identifier.",
		"profile": "Allow access to your basic profile (username and display information).",
		"email":   "Allow access to your email address.",
	}
	for _, scope := range display {
		if want, ok := expected[scope.Name]; !ok {
			t.Fatalf("unexpected scope %s", scope.Name)
		} else if scope.Description != want {
			t.Fatalf("scope %s description mismatch, got %q want %q", scope.Name, scope.Description, want)
		}
		delete(expected, scope.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing scopes in display: %+v", expected)
	}
}

func TestEnforceClientScopePolicyAllowsConfiguredScopes(t *testing.T) {
	client := oauth.Client{Scopes: []string{"openid", "profile", "offline_access"}}
	requested := []string{"openid", "profile", "offline_access", "profile"}

	filtered, err := enforceClientScopePolicy(requested, client)
	if err != nil {
		t.Fatalf(unexpectedErrorFmt, err)
	}

	want := []string{"openid", "profile", "offline_access"}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf(unexpectedScopesFmt, filtered, want)
	}
}

func TestEnforceClientScopePolicyRejectsUnconfiguredScope(t *testing.T) {
	client := oauth.Client{Scopes: []string{"openid", "profile"}}
	requested := []string{"openid", "offline_access"}

	_, err := enforceClientScopePolicy(requested, client)
	if err == nil {
		t.Fatal("expected error for disallowed scope")
	}
}

func TestEnforceClientScopePolicyAllowsDefaultScopes(t *testing.T) {
	client := oauth.Client{Scopes: nil}
	requested := []string{"openid", "profile"}

	filtered, err := enforceClientScopePolicy(requested, client)
	if err != nil {
		t.Fatalf(unexpectedErrorFmt, err)
	}

	want := []string{"openid", "profile"}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf(unexpectedScopesFmt, filtered, want)
	}
}

func TestEnforceClientScopePolicyFallsBackToOpenID(t *testing.T) {
	t.Parallel()

	client := oauth.Client{Scopes: []string{"openid", "profile"}}
	requested := []string{"   ", "", "\t"}

	filtered, err := enforceClientScopePolicy(requested, client)
	if err != nil {
		t.Fatalf(unexpectedErrorFmt, err)
	}

	want := []string{"openid"}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf(unexpectedScopesFmt, filtered, want)
	}
}

func TestAllowedScopesForClientEnsuresOpenID(t *testing.T) {
	client := oauth.Client{Scopes: []string{"profile"}}

	allowed := allowedScopesForClient(client)
	if _, ok := allowed["openid"]; !ok {
		t.Fatal("expected openid to be allowed")
	}
	if _, ok := allowed["profile"]; !ok {
		t.Fatal("expected profile to be allowed")
	}
	if _, ok := allowed["email"]; ok {
		t.Fatal("did not expect email to be allowed")
	}
}

func TestOIDCTokenHandlerRoutesRefreshGrant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf(sqlMockErrFmt, err)
	}
	defer db.Close()

	originalService := oauthService
	defer func() { oauthService = originalService }()

	oauthService = oauth.Service{DB: db}

	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`)).
		WithArgs(testClientID).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id",
			"client_secret",
			"name",
			"redirect_uris",
			"scopes",
			"grant_types",
			"response_types",
			"created_at",
			"updated_at",
		}).
			AddRow(
				testClientID,
				"",
				testClientName,
				pq.StringArray{testCallbackURL},
				pq.StringArray{"openid"},
				pq.StringArray{"authorization_code", "refresh_token"},
				pq.StringArray{"code"},
				now,
				now,
			))

	form := url.Values{}
	form.Set("grant_type", "REFRESH_TOKEN")
	form.Set("client_id", testClientID)

	req := httptest.NewRequest(http.MethodPost, testTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set(headerContentType, mimeFormURLEnc)

	rr := httptest.NewRecorder()
	oidcTokenHandler(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf(unexpectedStatusFmt, resp.StatusCode, http.StatusBadRequest)
	}

	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf(decodeResponseFmt, err)
	}
	if payload["error"] != "invalid_request" {
		t.Fatalf(unexpectedErrorCodeFmt, payload["error"], "invalid_request")
	}
	if payload["error_description"] != "refresh_token required" {
		t.Fatalf(unexpectedDescriptionFmt, payload["error_description"], "refresh_token required")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf(unmetExpectationsFmt, err)
	}
}

func TestOIDCTokenHandlerRequiresGrantType(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf(sqlMockErrFmt, err)
	}
	defer db.Close()

	originalService := oauthService
	defer func() { oauthService = originalService }()

	oauthService = oauth.Service{DB: db}

	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`)).
		WithArgs(testClientID).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id",
			"client_secret",
			"name",
			"redirect_uris",
			"scopes",
			"grant_types",
			"response_types",
			"created_at",
			"updated_at",
		}).
			AddRow(
				testClientID,
				"",
				testClientName,
				pq.StringArray{testCallbackURL},
				pq.StringArray{"openid"},
				pq.StringArray{"authorization_code"},
				pq.StringArray{"code"},
				now,
				now,
			))

	form := url.Values{}
	form.Set("client_id", testClientID)

	req := httptest.NewRequest(http.MethodPost, testTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set(headerContentType, mimeFormURLEnc)

	rr := httptest.NewRecorder()
	oidcTokenHandler(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf(unexpectedStatusFmt, resp.StatusCode, http.StatusBadRequest)
	}

	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf(decodeResponseFmt, err)
	}
	if payload["error"] != "invalid_request" {
		t.Fatalf(unexpectedErrorCodeFmt, payload["error"], "invalid_request")
	}
	if payload["error_description"] != "grant_type required" {
		t.Fatalf(unexpectedDescriptionFmt, payload["error_description"], "grant_type required")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf(unmetExpectationsFmt, err)
	}
}

func TestOIDCTokenHandlerRejectsUnauthorizedGrant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf(sqlMockErrFmt, err)
	}
	defer db.Close()

	originalService := oauthService
	defer func() { oauthService = originalService }()

	oauthService = oauth.Service{DB: db}

	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`)).
		WithArgs(testClientID).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id",
			"client_secret",
			"name",
			"redirect_uris",
			"scopes",
			"grant_types",
			"response_types",
			"created_at",
			"updated_at",
		}).
			AddRow(
				testClientID,
				"",
				testClientName,
				pq.StringArray{testCallbackURL},
				pq.StringArray{"openid"},
				pq.StringArray{"authorization_code"},
				pq.StringArray{"code"},
				now,
				now,
			))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", testClientID)

	req := httptest.NewRequest(http.MethodPost, testTokenPath, strings.NewReader(form.Encode()))
	req.Header.Set(headerContentType, mimeFormURLEnc)

	rr := httptest.NewRecorder()
	oidcTokenHandler(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf(unexpectedStatusFmt, resp.StatusCode, http.StatusBadRequest)
	}

	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf(decodeResponseFmt, err)
	}
	if payload["error"] != "unauthorized_client" {
		t.Fatalf(unexpectedErrorCodeFmt, payload["error"], "unauthorized_client")
	}
	if payload["error_description"] != "grant type not allowed for this client" {
		t.Fatalf(unexpectedDescriptionFmt, payload["error_description"], "grant type not allowed for this client")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf(unmetExpectationsFmt, err)
	}
}

func TestClientAllowsGrant(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		client oauth.Client
		grant  string
		allow  bool
	}{
		"defaults to authorization_code": {
			client: oauth.Client{},
			grant:  "authorization_code",
			allow:  true,
		},
		"defaults reject refresh": {
			client: oauth.Client{},
			grant:  "refresh_token",
			allow:  false,
		},
		"honors configured list": {
			client: oauth.Client{GrantTypes: []string{"authorization_code", "refresh_token"}},
			grant:  "refresh_token",
			allow:  true,
		},
		"normalizes casing and whitespace": {
			client: oauth.Client{GrantTypes: []string{"  REFRESH_TOKEN  "}},
			grant:  "  ReFrEsH_ToKeN  ",
			allow:  true,
		},
		"rejects unknown grant": {
			client: oauth.Client{GrantTypes: []string{"authorization_code"}},
			grant:  "password",
			allow:  false,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			allowed := clientAllowsGrant(tc.client, tc.grant)
			if allowed != tc.allow {
				t.Fatalf("clientAllowsGrant(%q) = %t, want %t", tc.grant, allowed, tc.allow)
			}
		})
	}
}
