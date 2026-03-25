package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auth-portal/configstore"
)

const (
	adminAuditEventsKey    = "events"
	adminLogBufferMaxLines = 500
	adminLogDefaultLimit   = 100
	adminLogMaxFetchLimit  = 500
)

type adminAuditPayload struct {
	Action  string `json:"action"`
	Subject string `json:"subject,omitempty"`
	Details string `json:"details,omitempty"`
}

type adminLogsHistoryEntry struct {
	Section   string    `json:"section"`
	Label     string    `json:"label"`
	Action    string    `json:"action"`
	Subject   string    `json:"subject,omitempty"`
	Details   string    `json:"details,omitempty"`
	Version   int64     `json:"version,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy string    `json:"updatedBy,omitempty"`
}

type adminLogsHistoryResponse struct {
	OK      bool                    `json:"ok"`
	Entries []adminLogsHistoryEntry `json:"entries"`
}

type adminLogStreamEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

type adminLogStreamResponse struct {
	OK      bool                  `json:"ok"`
	Cursor  int64                 `json:"cursor"`
	Entries []adminLogStreamEntry `json:"entries"`
}

type adminLogTap struct {
	mu      sync.Mutex
	max     int
	nextID  int64
	lines   []adminLogStreamEntry
	partial bytes.Buffer
}

func newAdminLogTap(max int) *adminLogTap {
	if max <= 0 {
		max = adminLogBufferMaxLines
	}
	return &adminLogTap{max: max}
}

func (t *adminLogTap) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, b := range p {
		if b == '\n' {
			t.flushLocked()
			continue
		}
		_ = t.partial.WriteByte(b)
	}
	return len(p), nil
}

func (t *adminLogTap) flushLocked() {
	line := strings.TrimRight(t.partial.String(), "\r")
	t.partial.Reset()
	if strings.TrimSpace(line) == "" {
		return
	}
	t.nextID++
	t.lines = append(t.lines, adminLogStreamEntry{
		ID:        t.nextID,
		Timestamp: time.Now().UTC(),
		Message:   line,
	})
	if len(t.lines) > t.max {
		t.lines = append([]adminLogStreamEntry(nil), t.lines[len(t.lines)-t.max:]...)
	}
}

func (t *adminLogTap) since(afterID int64, limit int) ([]adminLogStreamEntry, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.partial.Len() > 0 {
		t.flushLocked()
	}
	if limit <= 0 || limit > adminLogMaxFetchLimit {
		limit = adminLogDefaultLimit
	}

	filtered := make([]adminLogStreamEntry, 0, minInt(limit, len(t.lines)))
	for _, entry := range t.lines {
		if entry.ID <= afterID {
			continue
		}
		filtered = append(filtered, entry)
		if len(filtered) >= limit {
			break
		}
	}
	return filtered, t.nextID
}

var (
	adminLogStream = newAdminLogTap(adminLogBufferMaxLines)
	adminLogOnce   sync.Once
)

func installAdminLogBuffer() {
	adminLogOnce.Do(func() {
		log.SetOutput(io.MultiWriter(os.Stderr, adminLogStream))
	})
}

func recordAdminAudit(ctx context.Context, section configstore.Section, actor, action, subject, details, reason string) {
	if configStore == nil {
		return
	}
	action = strings.TrimSpace(action)
	subject = strings.TrimSpace(subject)
	details = strings.TrimSpace(details)
	reason = strings.TrimSpace(reason)
	if action == "" {
		return
	}
	if reason == "" {
		reason = action
		if subject != "" {
			reason = fmt.Sprintf("%s: %s", reason, subject)
		}
		if details != "" {
			reason = fmt.Sprintf("%s (%s)", reason, details)
		}
	}
	if err := configStore.AppendHistory(ctx, section, adminAuditPayload{
		Action:  action,
		Subject: subject,
		Details: details,
	}, configstore.UpdateOptions{
		Key:       adminAuditEventsKey,
		UpdatedBy: strings.TrimSpace(actor),
		Reason:    sanitizeAdminReason(reason),
	}); err != nil {
		log.Printf("admin audit failed for %s: %v", section, err)
	}
}

func adminLogsHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if configStore == nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "config store unavailable"})
		return
	}

	limit := adminLogDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > adminLogMaxFetchLimit {
		limit = adminLogMaxFetchLimit
	}

	type historySource struct {
		section configstore.Section
		output  string
		key     string
		label   string
		action  string
	}
	sources := []historySource{
		{section: configstore.SectionProviders, output: "providers", key: configstore.SectionDocumentKey, label: "Providers", action: "Configuration updated"},
		{section: configstore.SectionSecurity, output: "security", key: configstore.SectionDocumentKey, label: "Security", action: "Configuration updated"},
		{section: configstore.SectionMFA, output: "mfa", key: configstore.SectionDocumentKey, label: "MFA", action: "Configuration updated"},
		{section: configstore.SectionAppSettings, output: "app-settings", key: configstore.SectionDocumentKey, label: "App Settings", action: "Configuration updated"},
		{section: configstore.SectionOAuth, output: "oauth", key: oauthHistoryKey, label: "OAuth Clients"},
		{section: configstore.SectionLDAPSync, output: "ldap-sync", key: configstore.SectionDocumentKey, label: "LDAP Sync", action: "Configuration updated"},
		{section: configstore.SectionBackups, output: "backups", key: adminAuditEventsKey, label: "Backups"},
		{section: configstore.SectionRBAC, output: "access-control", key: adminAuditEventsKey, label: "Access Control"},
	}

	entries := make([]adminLogsHistoryEntry, 0, limit)
	for _, source := range sources {
		history, err := configStore.History(r.Context(), source.section, source.key, limit)
		if err != nil {
			log.Printf("admin logs history failed for %s/%s: %v", source.section, source.key, err)
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "history lookup failed"})
			return
		}
		for _, item := range history {
			entry := adminLogsHistoryEntry{
				Section:   source.output,
				Label:     source.label,
				Action:    source.action,
				Version:   item.Version,
				UpdatedAt: item.UpdatedAt.UTC(),
				UpdatedBy: strings.TrimSpace(item.UpdatedBy),
				Details:   strings.TrimSpace(item.Reason),
			}
			if source.key == configstore.SectionDocumentKey {
				if entry.Action == "" {
					entry.Action = "Configuration updated"
				}
			} else {
				entry = mergeAuditPayload(entry, item.Value)
				if entry.Action == "" {
					entry.Action = "Updated"
				}
				if entry.Details == "" {
					entry.Details = strings.TrimSpace(item.Reason)
				}
			}
			entries = append(entries, entry)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].UpdatedAt.Equal(entries[j].UpdatedAt) {
			return entries[i].Version > entries[j].Version
		}
		return entries[i].UpdatedAt.After(entries[j].UpdatedAt)
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}

	respondJSON(w, http.StatusOK, adminLogsHistoryResponse{
		OK:      true,
		Entries: entries,
	})
}

func mergeAuditPayload(entry adminLogsHistoryEntry, raw json.RawMessage) adminLogsHistoryEntry {
	var payload adminAuditPayload
	if len(raw) == 0 || json.Unmarshal(raw, &payload) != nil {
		return entry
	}
	if action := strings.TrimSpace(payload.Action); action != "" {
		entry.Action = action
	}
	if subject := strings.TrimSpace(payload.Subject); subject != "" {
		entry.Subject = subject
	}
	if details := strings.TrimSpace(payload.Details); details != "" {
		entry.Details = details
	}
	var rawFields map[string]any
	if json.Unmarshal(raw, &rawFields) == nil {
		if entry.Subject == "" {
			if name := stringifyAuditField(rawFields["name"]); name != "" {
				entry.Subject = name
			} else if clientID := stringifyAuditField(rawFields["clientId"]); clientID != "" {
				entry.Subject = clientID
			}
		}
		if entry.Details == "" {
			if clientID := stringifyAuditField(rawFields["clientId"]); clientID != "" && clientID != entry.Subject {
				entry.Details = clientID
			}
		}
	}
	return entry
}

func stringifyAuditField(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func adminLogsStreamHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	var (
		cursor int64
		limit  = adminLogDefaultLimit
	)
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v >= 0 {
			cursor = v
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}

	entries, latestCursor := adminLogStream.since(cursor, limit)
	respondJSON(w, http.StatusOK, adminLogStreamResponse{
		OK:      true,
		Cursor:  latestCursor,
		Entries: entries,
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
