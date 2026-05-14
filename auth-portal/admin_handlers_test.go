package main

import (
	"encoding/json"
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
		LoginExtraLinkURL:     "/docs",
		LoginExtraLinkText:    "Docs",
		PortalAppName:         "North Ridge Portal",
		PortalLogoURL:         "/static/north-ridge-logo.png",
		PortalBackgroundURL:   "/static/north-ridge-background.jpg",
		PortalBackgroundMode:  "fit",
		LoginBodyText:         "Sign in with your {{providerName}} account to continue.",
		AuthorizedTitleText:   "Welcome, {{username}}",
		AuthorizedBodyText:    "Your access to {{appName}} is active.",
		UnauthorizedTitleText: "Access Pending",
		UnauthorizedBodyText:  "Access to {{appName}} is pending review.",
		DisableFooter:         true,
		UnauthRequestEmail:    "admin@example.com",
		UnauthRequestSubject:  "Need Access",
		PortalBackgroundColor: "#0b1020",
		PortalModalColor:      "#111827",
		PortalTitleColor:      "#e5e7eb",
		PortalBodyTextColor:   "#94a3b8",
		ServiceLinks: []AppServiceLink{
			{Name: "Home", URL: "/home", Color: "#0a5a35"},
			{Name: "Library", URL: "https://library.example.com", Color: "#1d4ed8"},
		},
	}
	normalizeAppSettingsConfig(&cfg)
	if err := validateAppSettingsConfig(cfg); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}

	invalid := AppSettingsConfig{
		LoginExtraLinkURL:  "ht!tp://bad",
		UnauthRequestEmail: "not-an-email",
		ServiceLinks: []AppServiceLink{
			{Name: "Bad", URL: "javascript:alert(1)"},
		},
	}
	normalizeAppSettingsConfig(&invalid)
	if validateAppSettingsConfig(invalid) == nil {
		t.Fatalf("expected validation error for invalid config")
	}

	invalidColor := AppSettingsConfig{
		ServiceLinks: []AppServiceLink{
			{Name: "Home", URL: "/home", Color: "green"},
		},
	}
	normalizeAppSettingsConfig(&invalidColor)
	if validateAppSettingsConfig(invalidColor) == nil {
		t.Fatalf("expected validation error for invalid service link color")
	}

	invalidBg := AppSettingsConfig{
		PortalBackgroundColor: "blue",
	}
	normalizeAppSettingsConfig(&invalidBg)
	if validateAppSettingsConfig(invalidBg) == nil {
		t.Fatalf("expected validation error for invalid portal background color")
	}

	invalidTitleColor := AppSettingsConfig{
		PortalTitleColor: "white",
	}
	normalizeAppSettingsConfig(&invalidTitleColor)
	if validateAppSettingsConfig(invalidTitleColor) == nil {
		t.Fatalf("expected validation error for invalid portal title color")
	}

	invalidLogo := AppSettingsConfig{
		PortalLogoURL: "javascript:alert(1)",
	}
	normalizeAppSettingsConfig(&invalidLogo)
	if validateAppSettingsConfig(invalidLogo) == nil {
		t.Fatalf("expected validation error for invalid portal logo URL")
	}

	invalidBackground := AppSettingsConfig{
		PortalBackgroundURL: "javascript:alert(1)",
	}
	normalizeAppSettingsConfig(&invalidBackground)
	if validateAppSettingsConfig(invalidBackground) == nil {
		t.Fatalf("expected validation error for invalid portal background URL")
	}

	invalidBackgroundMode := AppSettingsConfig{
		PortalBackgroundMode: "sideways",
	}
	normalizeAppSettingsConfig(&invalidBackgroundMode)
	if validateAppSettingsConfig(invalidBackgroundMode) == nil {
		t.Fatalf("expected validation error for invalid portal background mode")
	}
}

func TestPortalBackgroundPresentationUsesCustomURL(t *testing.T) {
	previous := runtimeConfigValue.Load()
	defer func() {
		if previous != nil {
			runtimeConfigValue.Store(previous)
			return
		}
		runtimeConfigValue.Store(RuntimeConfig{AppSettings: defaultAppSettingsConfig()})
	}()

	runtimeConfigValue.Store(RuntimeConfig{
		AppSettings: AppSettingsConfig{
			PortalBackgroundColor: "#ffffff",
			PortalBackgroundURL:   "/static/custom-background.jpg",
			PortalBackgroundMode:  "fit",
		},
	})

	color, bgURL, mode := portalBackgroundPresentation()
	if bgURL != "/static/custom-background.jpg" {
		t.Fatalf("expected custom background URL, got %q", bgURL)
	}
	if mode != "bg-mode-image bg-image-fit" {
		t.Fatalf("expected image mode, got %q", mode)
	}
	if color != "#0b1020" {
		t.Fatalf("expected neutral fallback color for image mode, got %q", color)
	}

	style := string(portalBackgroundStyle(color, bgURL))
	if style != `--portal-bg-color: #0b1020; --portal-bg-image: url("/static/custom-background.jpg");` {
		t.Fatalf("unexpected background style: %q", style)
	}
}

func TestParseLDAPSyncPayload(t *testing.T) {
	raw := []byte(`{
		"ldapHost":" ldap://openldap:389 ",
		"ldapAdminDn":" cn=admin,dc=authportal,dc=local ",
		"ldapAdminPassword":" secret ",
		"baseDn":" ou=users,dc=authportal,dc=local ",
		"ldapStartTls":true,
		"deleteStaleEntries":true,
		"scheduleEnabled":true,
		"scheduleFrequency":"weekly",
		"scheduleTimeOfDay":"03:30",
		"scheduleDayOfWeek":"friday"
	}`)

	cfg, err := parseLDAPSyncPayload(raw)
	if err != nil {
		t.Fatalf("parseLDAPSyncPayload: %v", err)
	}
	if cfg.LDAPHost != "ldap://openldap:389" {
		t.Fatalf("unexpected host: %q", cfg.LDAPHost)
	}
	if cfg.LDAPAdminDN != "cn=admin,dc=authportal,dc=local" {
		t.Fatalf("unexpected admin DN: %q", cfg.LDAPAdminDN)
	}
	if cfg.BaseDN != "ou=users,dc=authportal,dc=local" {
		t.Fatalf("unexpected base DN: %q", cfg.BaseDN)
	}
	if !cfg.LDAPStartTLS {
		t.Fatalf("expected StartTLS to be preserved")
	}
	if !cfg.DeleteStaleEntries {
		t.Fatalf("expected delete stale flag to be preserved")
	}
	if !cfg.ScheduleEnabled || cfg.ScheduleFrequency != "weekly" || cfg.ScheduleTimeOfDay != "03:30" || cfg.ScheduleDayOfWeek != "friday" {
		t.Fatalf("unexpected schedule config: %+v", cfg)
	}

	_, err = parseLDAPSyncPayload([]byte(`[]`))
	if err == nil {
		t.Fatalf("expected validation error for malformed ldap sync config")
	}

	_, err = parseLDAPSyncPayload([]byte(`{"ldapHost":"ldap://openldap:389","ldapAdminDn":"cn=admin,dc=authportal,dc=local","baseDn":"ou=users,dc=authportal,dc=local","scheduleFrequency":"weekly","scheduleTimeOfDay":"03:30","scheduleDayOfWeek":"noday"}`))
	if err == nil {
		t.Fatalf("expected validation error for invalid ldap sync weekday")
	}
}

func TestParseLDAPSyncPayloadPreservesInactiveScheduleFields(t *testing.T) {
	raw := []byte(`{
		"ldapHost":"ldap://openldap:389",
		"ldapAdminDn":"cn=admin,dc=authportal,dc=local",
		"ldapAdminPassword":"secret",
		"baseDn":"ou=users,dc=authportal,dc=local",
		"scheduleEnabled":true,
		"scheduleFrequency":"hourly",
		"scheduleTimeOfDay":"03:30",
		"scheduleDayOfWeek":"friday",
		"scheduleMinute":0
	}`)

	cfg, err := parseLDAPSyncPayload(raw)
	if err != nil {
		t.Fatalf("parseLDAPSyncPayload: %v", err)
	}
	if cfg.ScheduleFrequency != "hourly" {
		t.Fatalf("unexpected frequency: %q", cfg.ScheduleFrequency)
	}
	if cfg.ScheduleTimeOfDay != "03:30" {
		t.Fatalf("expected time to be preserved, got %q", cfg.ScheduleTimeOfDay)
	}
	if cfg.ScheduleDayOfWeek != "friday" {
		t.Fatalf("expected weekday to be preserved, got %q", cfg.ScheduleDayOfWeek)
	}
	if cfg.ScheduleMinute != 0 {
		t.Fatalf("expected minute 0 to be preserved, got %d", cfg.ScheduleMinute)
	}
}

func TestLDAPSyncConfigJSONKeepsZeroMinute(t *testing.T) {
	cfg := LDAPSyncConfig{
		LDAPHost:          "ldap://openldap:389",
		LDAPAdminDN:       "cn=admin,dc=authportal,dc=local",
		LDAPAdminPassword: "secret",
		BaseDN:            "ou=users,dc=authportal,dc=local",
		ScheduleEnabled:   true,
		ScheduleFrequency: "hourly",
		ScheduleMinute:    0,
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	value, ok := decoded["scheduleMinute"]
	if !ok {
		t.Fatalf("expected scheduleMinute to be present in json: %s", string(raw))
	}
	if value.(float64) != 0 {
		t.Fatalf("expected scheduleMinute to be 0, got %v", value)
	}
}
