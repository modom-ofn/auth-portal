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
	adminLogConfigUpdated  = "Configuration updated"
)

type adminLogHistorySource struct {
	section configstore.Section
	output  string
	key     string
	label   string
	action  string
}

var adminLogHistorySources = []adminLogHistorySource{
	{section: configstore.SectionProviders, output: "providers", key: configstore.SectionDocumentKey, label: "Providers", action: adminLogConfigUpdated},
	{section: configstore.SectionSecurity, output: "security", key: configstore.SectionDocumentKey, label: "Security", action: adminLogConfigUpdated},
	{section: configstore.SectionMFA, output: "mfa", key: configstore.SectionDocumentKey, label: "MFA", action: adminLogConfigUpdated},
	{section: configstore.SectionAppSettings, output: "app-settings", key: configstore.SectionDocumentKey, label: "App Settings", action: adminLogConfigUpdated},
	{section: configstore.SectionOAuth, output: "oauth", key: oauthHistoryKey, label: "OAuth Clients"},
	{section: configstore.SectionLDAPSync, output: "ldap-sync", key: configstore.SectionDocumentKey, label: "LDAP Sync", action: adminLogConfigUpdated},
	{section: configstore.SectionBackups, output: "backups", key: adminAuditEventsKey, label: "Backups"},
	{section: configstore.SectionRBAC, output: "access-control", key: adminAuditEventsKey, label: "Access Control"},
}

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

	entries := make([]adminLogsHistoryEntry, 0, limit)
	for _, source := range adminLogHistorySources {
		sourceEntries, err := loadAdminLogHistoryEntries(r.Context(), source, limit)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "history lookup failed"})
			return
		}
		entries = append(entries, sourceEntries...)
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

func loadAdminLogHistoryEntries(ctx context.Context, source adminLogHistorySource, limit int) ([]adminLogsHistoryEntry, error) {
	history, err := configStore.History(ctx, source.section, source.key, limit)
	if err != nil {
		log.Printf("admin logs history failed for %s/%s: %v", source.section, source.key, err)
		return nil, err
	}
	entries := make([]adminLogsHistoryEntry, 0, len(history))
	for _, item := range history {
		entries = append(entries, buildAdminLogHistoryEntry(source, item))
	}
	return entries, nil
}

func buildAdminLogHistoryEntry(source adminLogHistorySource, item configstore.HistoryEntry) adminLogsHistoryEntry {
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
		return ensureAdminLogDefaults(entry, adminLogConfigUpdated, item.Reason)
	}
	return ensureAdminLogDefaults(mergeAuditPayload(entry, item.Value), "Updated", item.Reason)
}

func ensureAdminLogDefaults(entry adminLogsHistoryEntry, action, reason string) adminLogsHistoryEntry {
	if entry.Action == "" {
		entry.Action = action
	}
	if entry.Details == "" {
		entry.Details = strings.TrimSpace(reason)
	}
	return entry
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
	rawFields, ok := decodeAuditRawFields(raw)
	if !ok {
		return entry
	}
	entry.Subject = mergeAuditSubject(entry.Subject, rawFields)
	entry.Details = mergeAuditDetails(entry.Details, entry.Subject, rawFields)
	return entry
}

func decodeAuditRawFields(raw json.RawMessage) (map[string]any, bool) {
	var rawFields map[string]any
	if json.Unmarshal(raw, &rawFields) != nil {
		return nil, false
	}
	return rawFields, true
}

func mergeAuditSubject(subject string, rawFields map[string]any) string {
	if subject != "" {
		return subject
	}
	for _, key := range []string{"name", "clientId"} {
		if value := stringifyAuditField(rawFields[key]); value != "" {
			return value
		}
	}
	return subject
}

func mergeAuditDetails(details, subject string, rawFields map[string]any) string {
	if details != "" {
		return details
	}
	clientID := stringifyAuditField(rawFields["clientId"])
	if clientID != "" && clientID != subject {
		return clientID
	}
	return details
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
