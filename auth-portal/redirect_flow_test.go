package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLoginRedirectTargetPreservesOIDCAuthorizeRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=a&redirect_uri=https%3A%2F%2Fapp.example%2Fcb", nil)
	got := loginRedirectTarget(req)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse redirect target: %v", err)
	}
	if u.Path != "/" {
		t.Fatalf("unexpected redirect path: got %q want %q", u.Path, "/")
	}
	if u.Query().Get("next") != req.URL.RequestURI() {
		t.Fatalf("unexpected next value: got %q want %q", u.Query().Get("next"), req.URL.RequestURI())
	}
}

func TestLoginRedirectTargetDefaultsForNonOIDC(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/home", nil)
	if got := loginRedirectTarget(req); got != "/" {
		t.Fatalf("unexpected redirect target: got %q want %q", got, "/")
	}
}

func TestWriteOIDCRedirectErrorAllowsAbsoluteHTTPRedirect(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	writeOIDCRedirectError(rr, req, "https://app.example/callback?x=1", "abc", "access_denied", "nope")

	resp := rr.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusFound)
	}
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if u.Scheme != "https" || u.Host != "app.example" || u.Path != "/callback" {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
	if u.Query().Get("error") != "access_denied" {
		t.Fatalf("missing error query in redirect: %q", loc)
	}
	if u.Query().Get("state") != "abc" {
		t.Fatalf("missing state query in redirect: %q", loc)
	}
}

func TestSanitizeOIDCContinueTarget(t *testing.T) {
	if got := sanitizeOIDCContinueTarget("/oidc/authorize?client_id=x"); got != "/oidc/authorize?client_id=x" {
		t.Fatalf("unexpected sanitized target: %q", got)
	}
	if got := sanitizeOIDCContinueTarget("https://evil.example/oidc/authorize"); got != "/home" {
		t.Fatalf("expected fallback for absolute URL, got %q", got)
	}
	if got := sanitizeOIDCContinueTarget("/home"); got != "/home" {
		t.Fatalf("expected fallback for non-oidc path, got %q", got)
	}
}
