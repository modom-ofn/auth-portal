package main

import (
	"reflect"
	"testing"
)

func TestSanitizeOAuthClientRequest(t *testing.T) {
	req := adminOAuthClientRequest{
		Name: " Test App ",
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://example.com/callback ",
		},
		Scopes: []string{"email", "profile"},
	}

	sanitized, err := sanitizeOAuthClientRequest(req)
	if err != nil {
		t.Fatalf("sanitizeOAuthClientRequest: %v", err)
	}
	if sanitized.Name != "Test App" {
		t.Fatalf("expected name to be trimmed, got %q", sanitized.Name)
	}
	expectedRedirects := []string{"https://example.com/callback"}
	if !reflect.DeepEqual(sanitized.RedirectURIs, expectedRedirects) {
		t.Fatalf("unexpected redirects: %+v", sanitized.RedirectURIs)
	}
	expectedScopes := []string{"email", "profile"}
	if !reflect.DeepEqual(sanitized.Scopes, expectedScopes) {
		t.Fatalf("unexpected scopes: %+v", sanitized.Scopes)
	}

	// Missing required fields should return errors.
	_, err = sanitizeOAuthClientRequest(adminOAuthClientRequest{})
	if err == nil {
		t.Fatalf("expected error for missing fields")
	}
	_, err = sanitizeOAuthClientRequest(adminOAuthClientRequest{
		Name:         "Test",
		RedirectURIs: []string{"http://"},
	})
	if err == nil {
		t.Fatalf("expected error for invalid redirect")
	}
}

func TestNormalizeAdminStringList(t *testing.T) {
	values := []string{" beta ", "alpha", "alpha", " "}
	normalized := normalizeAdminStringList(values)
	expected := []string{"alpha", "beta"}
	if !reflect.DeepEqual(normalized, expected) {
		t.Fatalf("unexpected normalized list: %+v", normalized)
	}
}

func TestValidateAppSettingsConfig(t *testing.T) {
	cfg := AppSettingsConfig{
		LoginExtraLinkURL:    "/docs",
		LoginExtraLinkText:   "Docs",
		UnauthRequestEmail:   "admin@example.com",
		UnauthRequestSubject: "Need Access",
	}
	normalizeAppSettingsConfig(&cfg)
	if err := validateAppSettingsConfig(cfg); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	invalid := AppSettingsConfig{
		LoginExtraLinkURL:  "ht!tp://bad",
		UnauthRequestEmail: "not-an-email",
	}
	normalizeAppSettingsConfig(&invalid)
	if err := validateAppSettingsConfig(invalid); err == nil {
		t.Fatalf("expected validation error for invalid config")
	}
}
