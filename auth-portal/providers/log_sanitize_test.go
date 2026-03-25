package providers

import (
	"strings"
	"testing"
)

func TestRedactURLForLogRedactsSensitiveQueryValues(t *testing.T) {
	raw := "https://example.com/callback?code=abc123&token=tok456&client_id=public"
	got := redactURLForLog(raw)
	if got == raw {
		t.Fatalf("expected URL to be sanitized")
	}
	if containsProviderSensitive(got, "abc123", "tok456") {
		t.Fatalf("expected sensitive query values to be redacted, got %q", got)
	}
}

func TestSanitizeLogTextRedactsJSONSecrets(t *testing.T) {
	raw := `{"AccessToken":"tok123","User":{"Name":"alice"},"password":"hunter2"}`
	got := sanitizeLogText(raw)
	if containsProviderSensitive(got, "tok123", "hunter2") {
		t.Fatalf("expected sensitive JSON values to be redacted, got %q", got)
	}
}

func TestSanitizedSnippetRedactsBodySecrets(t *testing.T) {
	raw := []byte(`{"error":"bad creds","AccessToken":"tok123","secret":"value"}`)
	got := sanitizedSnippet(raw, 200)
	if containsProviderSensitive(got, "tok123", "value") {
		t.Fatalf("expected snippet to redact secrets, got %q", got)
	}
}

func containsProviderSensitive(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}
