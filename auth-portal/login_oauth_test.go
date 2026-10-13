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

func TestLoginCancelValidatesCallbackAndPreservesState(t *testing.T) {
	for _, callback := range []string{"https://app.example/callback", "https://evil.example/callback"} {
		t.Run(callback, func(t *testing.T) {
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
			if callback == "https://evil.example/callback" {
				if w.Code != 400 || w.Header().Get("Location") != "" {
					t.Fatalf("unsafe response: %d", w.Code)
				}
			} else {
				if w.Code != 200 {
					t.Fatalf("status %d: %s", w.Code, w.Body.String())
				}
				var result struct{ Redirect string }
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				dest, _ := url.Parse(result.Redirect)
				if dest.Host != "app.example" || dest.Query().Get("error") != "access_denied" || dest.Query().Get("state") != "original-state" || dest.Query().Get("code") != "" {
					t.Fatalf("bad callback: %s", result.Redirect)
				}
				if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
					t.Fatal("PIN not cleared")
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
