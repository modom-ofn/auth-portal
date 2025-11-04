package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"auth-portal/configstore"
)

type adminConfigSectionProviders struct {
	Version int64           `json:"version"`
	Config  ProvidersConfig `json:"config"`
}

type adminConfigSectionSecurity struct {
	Version int64          `json:"version"`
	Config  SecurityConfig `json:"config"`
}

type adminConfigSectionMFA struct {
	Version int64     `json:"version"`
	Config  MFAConfig `json:"config"`
}

type adminConfigResponse struct {
	OK        bool                        `json:"ok"`
	Providers adminConfigSectionProviders `json:"providers"`
	Security  adminConfigSectionSecurity  `json:"security"`
	MFA       adminConfigSectionMFA       `json:"mfa"`
	LoadedAt  time.Time                   `json:"loadedAt"`
}

type adminConfigUpdateRequest struct {
	Version int64           `json:"version"`
	Reason  string          `json:"reason"`
	Config  json.RawMessage `json:"config"`
}

type adminConfigHistoryEntry struct {
	Version   int64           `json:"version"`
	UpdatedAt time.Time       `json:"updatedAt"`
	UpdatedBy string          `json:"updatedBy,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Config    json.RawMessage `json:"config"`
}

type adminConfigHistoryResponse struct {
	OK      bool                      `json:"ok"`
	Section string                    `json:"section"`
	Entries []adminConfigHistoryEntry `json:"entries"`
}

func adminConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	cfg := currentRuntimeConfig()
	respondJSON(w, http.StatusOK, buildAdminConfigResponse(cfg))
}

func adminConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	vars := mux.Vars(r)
	sectionKey := strings.ToLower(strings.TrimSpace(vars["section"]))

	section, err := sectionFromKey(sectionKey)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown config section"})
		return
	}

	var req adminConfigUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
		return
	}

	if len(req.Config) == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "config payload required"})
		return
	}

	username := usernameFrom(r.Context())
	if username == "" {
		username = "admin"
	}

	var payload any
	var normalized interface{}

	switch section {
	case configstore.SectionProviders:
		var cfg ProvidersConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid providers config"})
			return
		}
		normalizeProvidersConfig(&cfg)
		if err := validateProvidersConfig(cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		payload = cfg
		normalized = cfg
	case configstore.SectionSecurity:
		var cfg SecurityConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid security config"})
			return
		}
		normalizeSecurityConfig(&cfg)
		if err := validateSecurityConfig(cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		payload = cfg
		normalized = cfg
	case configstore.SectionMFA:
		var cfg MFAConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid mfa config"})
			return
		}
		normalizeMFAConfig(&cfg)
		if err := validateMFAConfig(cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		payload = cfg
		normalized = cfg
	default:
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unsupported section"})
		return
	}

	sanitizedReason := strings.TrimSpace(req.Reason)
	if len(sanitizedReason) > 200 {
		sanitizedReason = sanitizedReason[:200]
	}

	snap, err := configStore.UpsertSection(r.Context(), section, payload, configstore.UpdateOptions{
		ExpectVersion: req.Version,
		UpdatedBy:     username,
		Reason:        sanitizedReason,
	})
	if err != nil {
		if errors.Is(err, configstore.ErrVersionMismatch) {
			respondJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "config version mismatch"})
			return
		}
		log.Printf("admin config update failed (%s): %v", sectionKey, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "config update failed"})
		return
	}

	runtimeCfg, err := loadRuntimeConfig(configStore)
	if err != nil {
		log.Printf("admin config reload failed (%s): %v", sectionKey, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "config reload failed"})
		return
	}
	if !snap.LoadedAt.IsZero() {
		runtimeCfg.LoadedAt = snap.LoadedAt
	}
	applyRuntimeConfig(runtimeCfg)

	if normalized != nil {
		respondJSON(w, http.StatusOK, buildAdminConfigResponse(runtimeCfg))
		return
	}
	adminConfigGetHandler(w, r)
}

func adminConfigHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	vars := mux.Vars(r)
	sectionKey := strings.ToLower(strings.TrimSpace(vars["section"]))
	section, err := sectionFromKey(sectionKey)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown config section"})
		return
	}

	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 200 {
		limit = 200
	}

	history, err := configStore.History(r.Context(), section, configstore.SectionDocumentKey, limit)
	if err != nil {
		log.Printf("admin config history failed (%s): %v", sectionKey, err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "history lookup failed"})
		return
	}

	resp := adminConfigHistoryResponse{
		OK:      true,
		Section: sectionKey,
		Entries: make([]adminConfigHistoryEntry, 0, len(history)),
	}
	for _, entry := range history {
		resp.Entries = append(resp.Entries, adminConfigHistoryEntry{
			Version:   entry.Version,
			UpdatedAt: entry.UpdatedAt,
			UpdatedBy: entry.UpdatedBy,
			Reason:    entry.Reason,
			Config:    entry.Value,
		})
	}

	respondJSON(w, http.StatusOK, resp)
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	cfg := currentRuntimeConfig()
	render(w, "admin.html", map[string]any{
		"ProviderDisplay": mediaProviderDisplay,
		"ConfigLoadedAt":  cfg.loadedAt().Format(time.RFC3339),
	})
}

func buildAdminConfigResponse(cfg RuntimeConfig) adminConfigResponse {
	return adminConfigResponse{
		OK: true,
		Providers: adminConfigSectionProviders{
			Version: cfg.ProvidersVersion,
			Config:  cfg.Providers,
		},
		Security: adminConfigSectionSecurity{
			Version: cfg.SecurityVersion,
			Config:  cfg.Security,
		},
		MFA: adminConfigSectionMFA{
			Version: cfg.MFAVersion,
			Config:  cfg.MFA,
		},
		LoadedAt: cfg.loadedAt(),
	}
}

func sectionFromKey(key string) (configstore.Section, error) {
	switch key {
	case "providers":
		return configstore.SectionProviders, nil
	case "security":
		return configstore.SectionSecurity, nil
	case "mfa":
		return configstore.SectionMFA, nil
	default:
		return "", errors.New("unknown section")
	}
}

func normalizeProvidersConfig(cfg *ProvidersConfig) {
	defaults := defaultProvidersConfig()
	cfg.Active = strings.ToLower(strings.TrimSpace(firstNonEmpty(cfg.Active, defaults.Active)))
	cfg.Plex.OwnerToken = strings.TrimSpace(cfg.Plex.OwnerToken)
	cfg.Plex.ServerMachineID = strings.TrimSpace(cfg.Plex.ServerMachineID)
	cfg.Plex.ServerName = strings.TrimSpace(cfg.Plex.ServerName)

	cfg.Emby.ServerURL = strings.TrimSpace(firstNonEmpty(cfg.Emby.ServerURL, defaults.Emby.ServerURL))
	cfg.Emby.AppName = strings.TrimSpace(firstNonEmpty(cfg.Emby.AppName, defaults.Emby.AppName))
	cfg.Emby.AppVersion = strings.TrimSpace(firstNonEmpty(cfg.Emby.AppVersion, defaults.Emby.AppVersion))
	cfg.Emby.APIKey = strings.TrimSpace(cfg.Emby.APIKey)
	cfg.Emby.OwnerUsername = strings.TrimSpace(cfg.Emby.OwnerUsername)
	cfg.Emby.OwnerID = strings.TrimSpace(cfg.Emby.OwnerID)

	cfg.Jellyfin.ServerURL = strings.TrimSpace(firstNonEmpty(cfg.Jellyfin.ServerURL, defaults.Jellyfin.ServerURL))
	cfg.Jellyfin.AppName = strings.TrimSpace(firstNonEmpty(cfg.Jellyfin.AppName, defaults.Jellyfin.AppName))
	cfg.Jellyfin.AppVersion = strings.TrimSpace(firstNonEmpty(cfg.Jellyfin.AppVersion, defaults.Jellyfin.AppVersion))
	cfg.Jellyfin.APIKey = strings.TrimSpace(cfg.Jellyfin.APIKey)
}

func normalizeSecurityConfig(cfg *SecurityConfig) {
	defaults := defaultSecurityConfig()
	cfg.SessionTTL = strings.TrimSpace(firstNonEmpty(cfg.SessionTTL, defaults.SessionTTL))
	cfg.SessionSameSite = strings.TrimSpace(strings.ToLower(firstNonEmpty(cfg.SessionSameSite, defaults.SessionSameSite)))
	cfg.SessionCookieDomain = strings.TrimSpace(cfg.SessionCookieDomain)
}

func normalizeMFAConfig(cfg *MFAConfig) {
	defaults := defaultMFAConfig()
	cfg.Issuer = strings.TrimSpace(firstNonEmpty(cfg.Issuer, defaults.Issuer))
}

func validateProvidersConfig(cfg ProvidersConfig) error {
	switch cfg.Active {
	case "plex", "emby", "jellyfin":
	default:
		return fmt.Errorf("unknown provider %q", cfg.Active)
	}

	checkURL := func(raw, name string) error {
		if raw == "" {
			return fmt.Errorf("%s URL is required", name)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid %s URL", name)
		}
		return nil
	}
	if err := checkURL(cfg.Emby.ServerURL, "emby"); err != nil {
		return err
	}
	if err := checkURL(cfg.Jellyfin.ServerURL, "jellyfin"); err != nil {
		return err
	}
	return nil
}

func validateSecurityConfig(cfg SecurityConfig) error {
	if _, err := time.ParseDuration(cfg.SessionTTL); err != nil {
		return fmt.Errorf("invalid session TTL: %v", err)
	}
	switch cfg.SessionSameSite {
	case "lax", "strict", "none":
	default:
		return fmt.Errorf("invalid session same-site value %q", cfg.SessionSameSite)
	}
	return nil
}

func validateMFAConfig(cfg MFAConfig) error {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return errors.New("mfa issuer is required")
	}
	return nil
}
