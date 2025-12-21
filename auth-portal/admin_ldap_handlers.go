package main

import (
	"context"
	"net/http"
	"time"
)

type adminLDAPStatus struct {
	OK                   bool               `json:"ok"`
	Enabled              bool               `json:"enabled"`
	Running              bool               `json:"running"`
	Config               ldapConfigPublic   `json:"config"`
	Mappings             []LDAPGroupMapping `json:"mappings"`
	LastRun              *ldapSyncResult    `json:"lastRun,omitempty"`
	Error                string             `json:"error,omitempty"`
	AutoSyncOnChange     bool               `json:"autoSyncOnChange"`
	AutoSyncDebounce     string             `json:"autoSyncDebounce,omitempty"`
	ScheduledSyncEnabled bool               `json:"scheduledSyncEnabled"`
	ScheduledSyncEvery   string             `json:"scheduledSyncEvery,omitempty"`
	NextScheduledRun     *time.Time         `json:"nextScheduledRun,omitempty"`
}

type ldapConfigPublic struct {
	Host        string `json:"host"`
	BaseDN      string `json:"baseDn"`
	GroupBaseDN string `json:"groupBaseDn"`
	StartTLS    bool   `json:"startTls"`
}

func adminLDAPStatusHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := currentRuntimeConfig().LDAP
	status := adminLDAPStatus{
		OK:                   true,
		Enabled:              cfg.Enabled,
		Config:               ldapConfigPublic{Host: cfg.Host, BaseDN: cfg.BaseDN, GroupBaseDN: cfg.GroupBaseDN, StartTLS: cfg.StartTLS},
		Mappings:             cfg.GroupRoleMappings,
		AutoSyncOnChange:     cfg.Enabled && cfg.AutoSyncOnChange,
		AutoSyncDebounce:     cfg.AutoSyncDebounce,
		ScheduledSyncEvery:   cfg.ScheduledSyncInterval,
		ScheduledSyncEnabled: cfg.Enabled && cfg.ScheduledSyncEnabled,
	}

	autoOn, schedOn, _, _, next := ldapScheduleSnapshot()
	status.AutoSyncOnChange = status.AutoSyncOnChange && autoOn
	status.ScheduledSyncEnabled = status.ScheduledSyncEnabled && schedOn
	if status.ScheduledSyncEnabled && !next.IsZero() {
		nextCopy := next
		status.NextScheduledRun = &nextCopy
	}

	ldapState.mu.Lock()
	status.Running = ldapState.running
	if !ldapState.last.StartedAt.IsZero() {
		last := ldapState.last
		status.LastRun = &last
		if !last.Success {
			status.Error = last.Message
		}
	}
	ldapState.mu.Unlock()

	respondJSON(w, http.StatusOK, status)
}

func adminLDAPSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	cfg := currentRuntimeConfig().LDAP
	if !cfg.Enabled {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "ldap sync disabled"})
		return
	}

	if !ldapMarkRunning() {
		ldapState.mu.Lock()
		last := ldapState.last
		ldapState.mu.Unlock()
		respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "ldap sync already running", "lastRun": last})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	result := runLDAPSync(ctx, cfg)

	ldapFinishRun(result)
	ldapScheduler.afterRun()

	resp := adminLDAPStatus{
		OK:                   result.Success,
		Enabled:              cfg.Enabled,
		Running:              false,
		Config:               ldapConfigPublic{Host: cfg.Host, BaseDN: cfg.BaseDN, GroupBaseDN: cfg.GroupBaseDN, StartTLS: cfg.StartTLS},
		Mappings:             cfg.GroupRoleMappings,
		LastRun:              &result,
		AutoSyncOnChange:     cfg.Enabled && cfg.AutoSyncOnChange,
		AutoSyncDebounce:     cfg.AutoSyncDebounce,
		ScheduledSyncEnabled: cfg.Enabled && cfg.ScheduledSyncEnabled,
		ScheduledSyncEvery:   cfg.ScheduledSyncInterval,
	}
	autoOn, schedOn, _, _, next := ldapScheduleSnapshot()
	resp.AutoSyncOnChange = resp.AutoSyncOnChange && autoOn
	resp.ScheduledSyncEnabled = resp.ScheduledSyncEnabled && schedOn
	if resp.ScheduledSyncEnabled && !next.IsZero() {
		nextCopy := next
		resp.NextScheduledRun = &nextCopy
	}
	if !result.Success {
		resp.Error = result.Message
	}

	respondJSON(w, http.StatusOK, resp)
}
