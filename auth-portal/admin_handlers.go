package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
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

func adminConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	cfg := currentRuntimeConfig()

	resp := adminConfigResponse{
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

	respondJSON(w, http.StatusOK, resp)
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

	switch section {
	case configstore.SectionProviders:
		var cfg ProvidersConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid providers config"})
			return
		}
		payload = cfg
	case configstore.SectionSecurity:
		var cfg SecurityConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid security config"})
			return
		}
		payload = cfg
	case configstore.SectionMFA:
		var cfg MFAConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid mfa config"})
			return
		}
		payload = cfg
	default:
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unsupported section"})
		return
	}

	sanitizedReason := strings.TrimSpace(req.Reason)
	if len(sanitizedReason) > 200 {
		sanitizedReason = sanitizedReason[:200]
	}

	_, err = configStore.UpsertSection(r.Context(), section, payload, configstore.UpdateOptions{
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
	applyRuntimeConfig(runtimeCfg)

	adminConfigGetHandler(w, r)
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
