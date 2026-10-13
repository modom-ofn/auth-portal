package main

import (
	"auth-portal/oauth"
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginContinuationRejectsExternalTargets(t *testing.T) {
	for _, raw := range []string{"https://evil.example/oidc/authorize", "//evil.example/oidc/authorize", "/oidc/authorize/other", "/oidc/authorize#fragment", "/home"} {
		if _, err := parseLoginContinuation(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func cancelLoginFixture(t *testing.T, callback string) *httptest.ResponseRecorder {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := oauthService
	defer func() { oauthService = old }()
	oauthService = oauth.Service{DB: db}
	mock.ExpectQuery("SELECT client_id, client_secret").WithArgs("test-client").WillReturnRows(
		sqlmock.NewRows([]string{"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at"}).AddRow("test-client", "", "Test", `{"https://app.example/callback"}`, `{"openid"}`, `{"authorization_code"}`, `{"code"}`, time.Now(), time.Now()))
	next := "/oidc/authorize?" + url.Values{"response_type": {"code"}, "client_id": {"test-client"}, "redirect_uri": {callback}, "state": {"original-state"}}.Encode()
	r := httptest.NewRequest("POST", "/oidc/login/cancel", strings.NewReader(url.Values{"next": {next}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	oidcLoginCancelHandler(w, r)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestLoginCancelRejectsUnregisteredCallback(t *testing.T) {
	w := cancelLoginFixture(t, "https://evil.example/callback")
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("unsafe response: %d", w.Code)
	}
}

func TestLoginCancelPreservesStateAndClearsPIN(t *testing.T) {
	w := cancelLoginFixture(t, "https://app.example/callback")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var result struct{ Redirect string }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	dest, err := url.Parse(result.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	if dest.Host != "app.example" {
		t.Fatalf("unregistered callback: %s", result.Redirect)
	}
	query := dest.Query()
	for key, expected := range map[string]string{"error": "access_denied", "state": "original-state", "code": ""} {
		if query.Get(key) != expected {
			t.Fatalf("incorrect callback field %s", key)
		}
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("unexpected cancellation cookies")
	}
	if cookies[0].MaxAge != -1 {
		t.Fatal("PIN not cleared")
	}
}
