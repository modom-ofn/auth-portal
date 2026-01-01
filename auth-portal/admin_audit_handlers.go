package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type adminAuditEvent struct {
	ID          int64           `json:"id"`
	Action      string          `json:"action"`
	TargetType  string          `json:"targetType"`
	TargetID    *int64          `json:"targetId,omitempty"`
	TargetLabel string          `json:"targetLabel,omitempty"`
	Actor       string          `json:"actor,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
}

type adminAuditListResponse struct {
	OK     bool              `json:"ok"`
	Events []adminAuditEvent `json:"events"`
}

func adminAuditListHandler(w http.ResponseWriter, r *http.Request) {
	limit := parseIntQuery(r, "limit", 50, 1, 200)
	beforeID := parseInt64Query(r, "before_id", 0)

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	query := `
SELECT id, action, target_type, target_id, target_label, actor, reason, metadata, created_at
  FROM admin_audit_events
`
	var args []any
	if beforeID > 0 {
		query += " WHERE id < $1 ORDER BY id DESC LIMIT $2"
		args = append(args, beforeID, limit)
	} else {
		query += " ORDER BY id DESC LIMIT $1"
		args = append(args, limit)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit lookup failed"})
		return
	}
	defer rows.Close()

	events := make([]adminAuditEvent, 0, limit)
	for rows.Next() {
		var (
			id          int64
			action      string
			targetType  string
			targetID    sql.NullInt64
			targetLabel sql.NullString
			actor       sql.NullString
			reason      sql.NullString
			metadata    []byte
			createdAt   time.Time
		)
		if err := rows.Scan(&id, &action, &targetType, &targetID, &targetLabel, &actor, &reason, &metadata, &createdAt); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit lookup failed"})
			return
		}
		var targetIDPtr *int64
		if targetID.Valid {
			val := targetID.Int64
			targetIDPtr = &val
		}
		event := adminAuditEvent{
			ID:          id,
			Action:      strings.TrimSpace(action),
			TargetType:  strings.TrimSpace(targetType),
			TargetID:    targetIDPtr,
			TargetLabel: strings.TrimSpace(targetLabel.String),
			Actor:       strings.TrimSpace(actor.String),
			Reason:      strings.TrimSpace(reason.String),
			CreatedAt:   createdAt.UTC(),
		}
		if len(metadata) > 0 {
			event.Metadata = json.RawMessage(metadata)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit lookup failed"})
		return
	}

	respondJSON(w, http.StatusOK, adminAuditListResponse{
		OK:     true,
		Events: events,
	})
}

func parseIntQuery(r *http.Request, key string, def, min, max int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if val < min {
		return min
	}
	if max > 0 && val > max {
		return max
	}
	return val
}

func parseInt64Query(r *http.Request, key string, def int64) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def
	}
	return val
}
