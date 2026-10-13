package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"auth-portal/configstore"
)

func readOIDCSection(section configstore.Section, target any) (int64, error) {
	if configStore == nil {
		return 0, nil
	}
	return configStore.Section(section, target)
}

func decodeOIDCConfigRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		respondJSON(w, 400, map[string]any{"ok": false, "error": "invalid configuration request"})
		return false
	}
	return true
}

func saveOIDCSection(w http.ResponseWriter, r *http.Request, section configstore.Section, payload any, version int64, reason string) bool {
	return saveOIDCSectionWithHook(w, r, section, payload, version, reason, nil)
}
func saveOIDCSectionWithHook(w http.ResponseWriter, r *http.Request, section configstore.Section, payload any, version int64, reason string, hook func(context.Context, *sql.Tx) error) bool {
	reason = strings.TrimSpace(reason)
	if version < 0 || reason == "" || len(reason) > 200 {
		respondJSON(w, 400, map[string]any{"ok": false, "error": "valid version and change reason required"})
		return false
	}
	if configStore == nil {
		respondJSON(w, 503, map[string]any{"ok": false, "error": "configuration store unavailable"})
		return false
	}
	_, err := configStore.UpsertSection(r.Context(), section, payload, configstore.UpdateOptions{RequireVersion: true, BeforeCommit: hook, ExpectVersion: version, UpdatedBy: usernameFrom(r.Context()), Reason: reason})
	if errors.Is(err, configstore.ErrVersionMismatch) {
		respondJSON(w, 409, map[string]any{"ok": false, "error": "configuration changed; reload before saving"})
		return false
	}
	if err != nil {
		respondJSON(w, 500, map[string]any{"ok": false, "error": "configuration update failed"})
		return false
	}
	return true
}

func validateOIDCClientIDs(ids []string) error {
	if len(ids) > 100 {
		return errors.New("too many client identifiers")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || seen[id] {
			return errors.New("missing, invalid or duplicate client")
		}
		seen[id] = true
	}
	return nil
}
