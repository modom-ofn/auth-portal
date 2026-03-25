package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var providerSensitiveQueryKeys = map[string]struct{}{
	"accesstoken":   {},
	"access_token":  {},
	"api_key":       {},
	"apikey":        {},
	"auth_token":    {},
	"authorization": {},
	"client_secret": {},
	"code":          {},
	"cookie":        {},
	"idtoken":       {},
	"id_token":      {},
	"password":      {},
	"refreshtoken":  {},
	"refresh_token": {},
	"secret":        {},
	"state":         {},
	"token":         {},
	"x-plex-token":  {},
}

var providerAuthHeaderPattern = regexp.MustCompile(`(?i)(authorization["=: ]+(?:[A-Za-z]+ )?)([^",\s]+)`)
var providerHeaderTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(x-emby-token["=: ]+)([^",\s]+)`),
	regexp.MustCompile(`(?i)(x-mediabrowser-token["=: ]+)([^",\s]+)`),
	regexp.MustCompile(`(?i)(x-plex-token["=: ]+)([^",\s]+)`),
}
var providerJSONSecretPattern = regexp.MustCompile(`(?i)("?(?:accesstoken|access_token|password|secret|client_secret|refreshtoken|refresh_token|idtoken|id_token|token|apikey|api_key|authorization)"?\s*:\s*")([^"]+)(")`)
var providerQuerySecretPattern = regexp.MustCompile(`(?i)((?:password|secret|token|apikey|api_key|client_secret|refresh_token|access_token)=)([^&\s]+)`)

func redactURLForLog(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return sanitizeLogText(raw)
	}
	query := parsed.Query()
	for key := range query {
		if _, ok := providerSensitiveQueryKeys[strings.ToLower(strings.TrimSpace(key))]; ok {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func sanitizeLogText(raw string) string {
	sanitized := strings.TrimSpace(raw)
	if sanitized == "" {
		return sanitized
	}

	var asJSON any
	if json.Unmarshal([]byte(sanitized), &asJSON) == nil {
		return marshalSanitizedJSON(asJSON)
	}

	sanitized = providerAuthHeaderPattern.ReplaceAllString(sanitized, `${1}[REDACTED]`)
	for _, pattern := range providerHeaderTokenPatterns {
		sanitized = pattern.ReplaceAllString(sanitized, `${1}[REDACTED]`)
	}
	sanitized = providerJSONSecretPattern.ReplaceAllString(sanitized, `${1}[REDACTED]${3}`)
	sanitized = providerQuerySecretPattern.ReplaceAllString(sanitized, `${1}[REDACTED]`)
	return sanitized
}

func marshalSanitizedJSON(value any) string {
	sanitized := sanitizeJSONValue(value)
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return "[REDACTED]"
	}
	return string(encoded)
}

func sanitizeJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			if _, ok := providerSensitiveQueryKeys[strings.ToLower(strings.TrimSpace(key))]; ok {
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = sanitizeJSONValue(child)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, child := range typed {
			out = append(out, sanitizeJSONValue(child))
		}
		return out
	default:
		return typed
	}
}

func sanitizedSnippet(raw []byte, n int) string {
	sanitized := sanitizeLogText(string(raw))
	if len(sanitized) > n {
		return fmt.Sprintf("%s…", sanitized[:n])
	}
	return sanitized
}
