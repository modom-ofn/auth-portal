package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const (
	errMethodNotAllowed   = "method not allowed"
	errBackupsUnavailable = "backups unavailable"
	errInvalidRequest     = "invalid request"
)

type adminBackupScheduleResponse struct {
	Enabled   bool       `json:"enabled"`
	Frequency string     `json:"frequency"`
	TimeOfDay string     `json:"timeOfDay,omitempty"`
	DayOfWeek string     `json:"dayOfWeek,omitempty"`
	Minute    int        `json:"minute,omitempty"`
	Sections  []string   `json:"sections"`
	Retention int        `json:"retention"`
	LastRun   *time.Time `json:"lastRun,omitempty"`
	NextRun   *time.Time `json:"nextRun,omitempty"`
}

type adminBackupFileResponse struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy,omitempty"`
	Sections  []string  `json:"sections"`
	Size      int64     `json:"size"`
}

type adminBackupListResponse struct {
	OK        bool                        `json:"ok"`
	Schedule  adminBackupScheduleResponse `json:"schedule"`
	Backups   []adminBackupFileResponse   `json:"backups"`
	Message   string                      `json:"message,omitempty"`
	Timestamp time.Time                   `json:"timestamp"`
}

type adminBackupCreateRequest struct {
	Sections []string `json:"sections"`
}

type adminBackupScheduleRequest struct {
	Enabled   bool     `json:"enabled"`
	Frequency string   `json:"frequency"`
	TimeOfDay string   `json:"timeOfDay"`
	DayOfWeek string   `json:"dayOfWeek"`
	Minute    int      `json:"minute"`
	Sections  []string `json:"sections"`
	Retention int      `json:"retention"`
}

func adminBackupsListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if backupSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": errBackupsUnavailable})
		return
	}

	files, err := backupSvc.ListBackups()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to list backups"})
		return
	}
	sched, next := backupSvc.ScheduleSnapshot()

	resp := adminBackupListResponse{
		OK:        true,
		Schedule:  mapScheduleResponse(sched, next),
		Backups:   make([]adminBackupFileResponse, 0, len(files)),
		Timestamp: time.Now().UTC(),
	}
	for _, file := range files {
		resp.Backups = append(resp.Backups, mapBackupFileResponse(file))
	}
	respondJSON(w, http.StatusOK, resp)
}

func adminBackupsCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if backupSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": errBackupsUnavailable})
		return
	}

	var req adminBackupCreateRequest
	if r.Body != nil {
		defer r.Body.Close()
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errInvalidRequest})
			return
		}
	}

	meta, err := backupSvc.CreateManualBackup(r.Context(), req.Sections, usernameFrom(r.Context()))
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to create backup"})
		return
	}
	if err := writeBackupAuditEvent(r.Context(), "backups.create", usernameFrom(r.Context()), map[string]any{
		"backup": mapBackupFileResponse(meta),
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit write failed"})
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"ok":     true,
		"backup": mapBackupFileResponse(meta),
	})
}

func adminBackupsScheduleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if backupSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": errBackupsUnavailable})
		return
	}

	var req adminBackupScheduleRequest
	if r.Body == nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errInvalidRequest})
		return
	}
	defer r.Body.Close()
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errInvalidRequest})
		return
	}

	schedule := backupSchedule{
		Enabled:   req.Enabled,
		Frequency: req.Frequency,
		TimeOfDay: req.TimeOfDay,
		DayOfWeek: req.DayOfWeek,
		Minute:    req.Minute,
		Sections:  req.Sections,
		Retention: req.Retention,
	}

	actor := usernameFrom(r.Context())
	if actor = strings.TrimSpace(actor); actor == "" {
		actor = "admin"
	}

	before, beforeNext := backupSvc.ScheduleSnapshot()
	updated, next, err := backupSvc.UpdateSchedule(r.Context(), schedule, actor)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if err := writeBackupAuditEvent(r.Context(), "backups.schedule.update", actor, map[string]any{
		"before": mapScheduleResponse(before, beforeNext),
		"after":  mapScheduleResponse(updated, next),
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit write failed"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"schedule": mapScheduleResponse(updated, next),
	})
}

func adminBackupsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if backupSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": errBackupsUnavailable})
		return
	}
	name := mux.Vars(r)["name"]
	if err := backupSvc.DeleteBackup(name); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := writeBackupAuditEvent(r.Context(), "backups.delete", usernameFrom(r.Context()), map[string]any{
		"name": name,
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit write failed"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func adminBackupsRestoreHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if backupSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": errBackupsUnavailable})
		return
	}

	name := mux.Vars(r)["name"]
	cfg, err := backupSvc.RestoreBackup(r.Context(), name, usernameFrom(r.Context()))
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := writeBackupAuditEvent(r.Context(), "backups.restore", usernameFrom(r.Context()), map[string]any{
		"name": name,
	}); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "audit write failed"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"config": buildAdminConfigResponse(cfg),
	})
}

func adminBackupsDownloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if backupSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": errBackupsUnavailable})
		return
	}

	name := mux.Vars(r)["name"]
	reader, createdAt, err := backupSvc.OpenBackup(name)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to read backup"})
		return
	}

	filename := path.Base(name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	if !createdAt.IsZero() {
		w.Header().Set("Last-Modified", createdAt.UTC().Format(http.TimeFormat))
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if _, err := w.Write(data); err != nil {
		log.Printf("backup download write failed for %s: %v", filename, err)
	}
}

func mapScheduleResponse(sched backupSchedule, next time.Time) adminBackupScheduleResponse {
	resp := adminBackupScheduleResponse{
		Enabled:   sched.Enabled,
		Frequency: sched.Frequency,
		TimeOfDay: sched.TimeOfDay,
		DayOfWeek: sched.DayOfWeek,
		Minute:    sched.Minute,
		Sections:  append([]string(nil), sched.Sections...),
		Retention: sched.Retention,
	}
	loc := appLocation
	if loc == nil {
		loc = time.UTC
	}
	if !sched.LastRun.IsZero() {
		last := sched.LastRun.In(loc)
		resp.LastRun = &last
	}
	if !next.IsZero() {
		nextLocal := next.In(loc)
		resp.NextRun = &nextLocal
	}
	return resp
}

func mapBackupFileResponse(meta backupMetadata) adminBackupFileResponse {
	return adminBackupFileResponse{
		Name:      meta.Name,
		CreatedAt: meta.CreatedAt.UTC(),
		CreatedBy: meta.CreatedBy,
		Sections:  append([]string(nil), meta.Sections...),
		Size:      meta.Size,
	}
}

func writeBackupAuditEvent(ctx context.Context, action, actor string, metadata map[string]any) error {
	if strings.TrimSpace(action) == "" {
		return errors.New("audit action required")
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err = db.ExecContext(ctx, `
INSERT INTO admin_audit_events (action, target_type, target_label, actor, metadata)
VALUES ($1, $2, $3, $4, $5)
`, action, "backups", "schedule", strings.TrimSpace(actor), meta)
	return err
}
