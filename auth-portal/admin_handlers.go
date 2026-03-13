package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"auth-portal/ldapsync"

	"github.com/gorilla/mux"

	"auth-portal/configstore"
	"auth-portal/oauth"
)

const (
	errClientIDRequired = "client id required"
	errClientNotFound   = "client not found"
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

type adminConfigSectionAppSettings struct {
	Version int64             `json:"version"`
	Config  AppSettingsConfig `json:"config"`
}

type adminConfigSectionLDAPSync struct {
	Version int64          `json:"version"`
	Config  LDAPSyncConfig `json:"config"`
}

type adminConfigResponse struct {
	OK          bool                          `json:"ok"`
	Providers   adminConfigSectionProviders   `json:"providers"`
	Security    adminConfigSectionSecurity    `json:"security"`
	MFA         adminConfigSectionMFA         `json:"mfa"`
	AppSettings adminConfigSectionAppSettings `json:"appSettings"`
	LDAPSync    adminConfigSectionLDAPSync    `json:"ldapSync"`
	LoadedAt    time.Time                     `json:"loadedAt"`
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

type adminOAuthClient struct {
	ClientID      string    `json:"clientId"`
	Name          string    `json:"name"`
	RedirectURIs  []string  `json:"redirectUris"`
	Scopes        []string  `json:"scopes"`
	GrantTypes    []string  `json:"grantTypes"`
	ResponseTypes []string  `json:"responseTypes"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type adminOAuthClientsResponse struct {
	OK      bool               `json:"ok"`
	Clients []adminOAuthClient `json:"clients"`
}

type adminOAuthClientResponse struct {
	OK           bool             `json:"ok"`
	Client       adminOAuthClient `json:"client"`
	ClientSecret string           `json:"clientSecret,omitempty"`
}

type adminOAuthClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirectUris"`
	Scopes       []string `json:"scopes"`
}

type adminLDAPSyncResponse struct {
	OK     bool                       `json:"ok"`
	Config adminConfigSectionLDAPSync `json:"config"`
	Status ldapSyncStatusView         `json:"status"`
	Runs   []ldapSyncRunRecord        `json:"runs"`
}

type adminLDAPSyncTestResponse struct {
	OK     bool                          `json:"ok"`
	Result ldapsync.ConnectionTestResult `json:"result"`
}

func adminConfigGetHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := currentRuntimeConfig()
	respondJSON(w, http.StatusOK, buildAdminConfigResponse(cfg))
}

func adminConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}

	vars := mux.Vars(r)
	sectionKey := strings.ToLower(strings.TrimSpace(vars["section"]))

	section, err := sectionFromKey(sectionKey)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "unknown config section"})
		return
	}

	req, err := decodeAdminConfigUpdateRequest(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	payload, err := buildConfigPayload(section, req.Config)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	username := usernameFrom(r.Context())
	if username == "" {
		username = "admin"
	}

	snap, err := configStore.UpsertSection(r.Context(), section, payload, configstore.UpdateOptions{
		ExpectVersion: req.Version,
		UpdatedBy:     username,
		Reason:        sanitizeAdminReason(req.Reason),
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

	respondJSON(w, http.StatusOK, buildAdminConfigResponse(runtimeCfg))
}

func decodeAdminConfigUpdateRequest(r *http.Request) (adminConfigUpdateRequest, error) {
	var req adminConfigUpdateRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		return req, errors.New("invalid request body")
	}
	if len(req.Config) == 0 {
		return req, errors.New("config payload required")
	}
	return req, nil
}

func buildConfigPayload(section configstore.Section, raw json.RawMessage) (any, error) {
	switch section {
	case configstore.SectionProviders:
		return parseProvidersPayload(raw)
	case configstore.SectionSecurity:
		return parseSecurityPayload(raw)
	case configstore.SectionMFA:
		return parseMFAPayload(raw)
	case configstore.SectionAppSettings:
		return parseAppSettingsPayload(raw)
	case configstore.SectionLDAPSync:
		return parseLDAPSyncPayload(raw)
	default:
		return nil, errors.New("unsupported section")
	}
}

func parseProvidersPayload(raw json.RawMessage) (ProvidersConfig, error) {
	var cfg ProvidersConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return cfg, errors.New("invalid providers config")
	}
	normalizeProvidersConfig(&cfg)
	if err := validateProvidersConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseSecurityPayload(raw json.RawMessage) (SecurityConfig, error) {
	var cfg SecurityConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return cfg, errors.New("invalid security config")
	}
	normalizeSecurityConfig(&cfg)
	if err := validateSecurityConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseMFAPayload(raw json.RawMessage) (MFAConfig, error) {
	var cfg MFAConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return cfg, errors.New("invalid mfa config")
	}
	normalizeMFAConfig(&cfg)
	if err := validateMFAConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseAppSettingsPayload(raw json.RawMessage) (AppSettingsConfig, error) {
	var cfg AppSettingsConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return cfg, errors.New("invalid app settings config")
	}
	normalizeAppSettingsConfig(&cfg)
	if err := validateAppSettingsConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseLDAPSyncPayload(raw json.RawMessage) (LDAPSyncConfig, error) {
	var cfg LDAPSyncConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return cfg, errors.New("invalid ldap sync config")
	}
	normalizeLDAPSyncConfig(&cfg)
	if err := validateLDAPSyncConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func sanitizeAdminReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 200 {
		return reason[:200]
	}
	return reason
}

func adminConfigHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
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

	if configStore == nil {
		log.Printf("admin config history unavailable: config store not initialized")
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "config store unavailable"})
		return
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

func adminOAuthClientsList(w http.ResponseWriter, r *http.Request) {
	clients, err := oauthService.ListClients(r.Context())
	if err != nil {
		log.Printf("admin oauth list: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "client list failed"})
		return
	}
	out := make([]adminOAuthClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, mapOAuthClient(c))
	}
	respondJSON(w, http.StatusOK, adminOAuthClientsResponse{
		OK:      true,
		Clients: out,
	})
}

func adminOAuthClientCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	var req adminOAuthClientRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	payload, err := sanitizeOAuthClientRequest(req)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	client, secret, err := oauthService.CreateClient(r.Context(), payload.Name, payload.RedirectURIs, payload.Scopes)
	if err != nil {
		log.Printf("admin oauth create: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "client create failed"})
		return
	}
	respondJSON(w, http.StatusOK, adminOAuthClientResponse{
		OK:           true,
		Client:       mapOAuthClient(client),
		ClientSecret: secret,
	})
}

func adminOAuthClientUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	clientID := strings.TrimSpace(mux.Vars(r)["id"])
	if clientID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errClientIDRequired})
		return
	}
	var req adminOAuthClientRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request"})
		return
	}
	payload, err := sanitizeOAuthClientRequest(req)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	client, err := oauthService.UpdateClient(r.Context(), clientID, payload.Name, payload.RedirectURIs, payload.Scopes)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": errClientNotFound})
			return
		}
		log.Printf("admin oauth update: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "client update failed"})
		return
	}
	respondJSON(w, http.StatusOK, adminOAuthClientResponse{
		OK:     true,
		Client: mapOAuthClient(client),
	})
}

func adminOAuthClientRotateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	clientID := strings.TrimSpace(mux.Vars(r)["id"])
	if clientID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errClientIDRequired})
		return
	}
	secret, err := oauthService.RotateClientSecret(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": errClientNotFound})
			return
		}
		log.Printf("admin oauth rotate: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "secret rotation failed"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"clientSecret": secret,
	})
}

func adminOAuthClientDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	clientID := strings.TrimSpace(mux.Vars(r)["id"])
	if clientID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errClientIDRequired})
		return
	}
	if err := oauthService.DeleteClient(r.Context(), clientID); err != nil {
		if errors.Is(err, oauth.ErrClientNotFound) {
			respondJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": errClientNotFound})
			return
		}
		log.Printf("admin oauth delete: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "client delete failed"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func adminPageHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := currentRuntimeConfig()
	render(w, "admin.html", map[string]any{
		"ProviderDisplay": mediaProviderDisplay,
		"ConfigLoadedAt":  cfg.loadedAt().Format(time.RFC3339),
		"AppTimeZone":     appTimeZone,
	})
}

func adminLDAPSyncGetHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := currentRuntimeConfig()
	status := ldapSyncStatusView{}
	runs := []ldapSyncRunRecord{}
	if manager := currentLDAPSyncManager(); manager != nil {
		var err error
		status, err = manager.Status(10)
		if err != nil {
			log.Printf("admin ldap sync status failed: %v", err)
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "ldap sync status unavailable"})
			return
		}
		runs, err = manager.ListRuns(10)
		if err != nil {
			log.Printf("admin ldap sync history failed: %v", err)
			respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "ldap sync history unavailable"})
			return
		}
	}
	respondJSON(w, http.StatusOK, adminLDAPSyncResponse{
		OK: true,
		Config: adminConfigSectionLDAPSync{
			Version: cfg.LDAPSyncVersion,
			Config:  cfg.LDAPSync,
		},
		Status: status,
		Runs:   runs,
	})
}

func adminLDAPSyncRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	manager := currentLDAPSyncManager()
	if manager == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "ldap sync unavailable"})
		return
	}
	actor := strings.TrimSpace(usernameFrom(r.Context()))
	if actor == "" {
		actor = "admin"
	}
	result, status, err := manager.Run(r.Context(), actor, "manual")
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, ldapsync.ErrRunInProgress) {
			statusCode = http.StatusConflict
		} else if strings.Contains(strings.ToLower(err.Error()), "required") {
			statusCode = http.StatusBadRequest
		}
		respondJSON(w, statusCode, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"result": result,
		"status": status,
	})
}

func adminLDAPSyncTestConnectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": errMethodNotAllowed})
		return
	}
	if ldapSyncSvc == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "ldap sync unavailable"})
		return
	}
	var raw json.RawMessage
	if json.NewDecoder(r.Body).Decode(&raw) != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid request body"})
		return
	}
	cfg, err := parseLDAPSyncPayload(raw)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	result, err := ldapSyncSvc.TestConnection(r.Context(), ldapsync.Config{
		LDAPHost:           cfg.LDAPHost,
		LDAPAdminDN:        cfg.LDAPAdminDN,
		LDAPAdminPassword:  cfg.LDAPAdminPassword,
		BaseDN:             cfg.BaseDN,
		LDAPStartTLS:       cfg.LDAPStartTLS,
		DeleteStaleEntries: cfg.DeleteStaleEntries,
	})
	if err != nil {
		respondJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, adminLDAPSyncTestResponse{
		OK:     true,
		Result: result,
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
		AppSettings: adminConfigSectionAppSettings{
			Version: cfg.AppSettingsVersion,
			Config:  cfg.AppSettings,
		},
		LDAPSync: adminConfigSectionLDAPSync{
			Version: cfg.LDAPSyncVersion,
			Config:  cfg.LDAPSync,
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
	case "app-settings":
		return configstore.SectionAppSettings, nil
	case "ldap-sync":
		return configstore.SectionLDAPSync, nil
	default:
		return "", errors.New("unknown section")
	}
}

func mapOAuthClient(c oauth.Client) adminOAuthClient {
	return adminOAuthClient{
		ClientID:      c.ClientID,
		Name:          strings.TrimSpace(c.Name),
		RedirectURIs:  append([]string(nil), c.RedirectURIs...),
		Scopes:        append([]string(nil), c.Scopes...),
		GrantTypes:    append([]string(nil), c.GrantTypes...),
		ResponseTypes: append([]string(nil), c.ResponseTypes...),
		CreatedAt:     c.CreatedAt.UTC(),
		UpdatedAt:     c.UpdatedAt.UTC(),
	}
}

func sanitizeOAuthClientRequest(req adminOAuthClientRequest) (adminOAuthClientRequest, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return adminOAuthClientRequest{}, errors.New("name is required")
	}
	redirects := normalizeAdminStringList(req.RedirectURIs)
	if len(redirects) == 0 {
		return adminOAuthClientRequest{}, errors.New("at least one redirect URI is required")
	}
	for _, uri := range redirects {
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return adminOAuthClientRequest{}, fmt.Errorf("invalid redirect URI: %s", uri)
		}
	}
	scopes := normalizeAdminStringList(req.Scopes)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return adminOAuthClientRequest{
		Name:         name,
		RedirectURIs: redirects,
		Scopes:       scopes,
	}, nil
}

func normalizeAdminStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	set := make(map[string]struct{}, len(values))
	for _, val := range values {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		set[val] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for val := range set {
		out = append(out, val)
	}
	sort.Strings(out)
	return out
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

func normalizeAppSettingsConfig(cfg *AppSettingsConfig) {
	defaults := defaultAppSettingsConfig()
	cfg.LoginExtraLinkURL = strings.TrimSpace(firstNonEmpty(cfg.LoginExtraLinkURL, defaults.LoginExtraLinkURL))
	cfg.LoginExtraLinkText = strings.TrimSpace(firstNonEmpty(cfg.LoginExtraLinkText, defaults.LoginExtraLinkText))
	cfg.UnauthRequestEmail = strings.TrimSpace(firstNonEmpty(cfg.UnauthRequestEmail, defaults.UnauthRequestEmail))
	cfg.UnauthRequestSubject = strings.TrimSpace(firstNonEmpty(cfg.UnauthRequestSubject, defaults.UnauthRequestSubject))
	cfg.PortalBackgroundColor = strings.TrimSpace(firstNonEmpty(cfg.PortalBackgroundColor, defaults.PortalBackgroundColor))
	cfg.PortalModalColor = strings.TrimSpace(firstNonEmpty(cfg.PortalModalColor, defaults.PortalModalColor))
	cfg.ServiceLinks = normalizeServiceLinks(cfg.ServiceLinks)
}

func normalizeServiceLinks(links []AppServiceLink) []AppServiceLink {
	if len(links) == 0 {
		return nil
	}
	normalized := make([]AppServiceLink, 0, len(links))
	seen := make(map[string]struct{}, len(links))
	for _, link := range links {
		name := strings.TrimSpace(link.Name)
		rawURL := strings.TrimSpace(link.URL)
		if name == "" || rawURL == "" {
			continue
		}
		key := strings.ToLower(name) + "|" + rawURL
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, AppServiceLink{
			Name:  name,
			URL:   rawURL,
			Color: strings.TrimSpace(link.Color),
		})
		if len(normalized) >= 20 {
			break
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
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

func validateOptionalPortalLink(raw string) error {
	link := strings.TrimSpace(raw)
	if link != "" && !isValidPortalLinkURL(link) {
		return errors.New("login extra link URL must be a relative path or absolute URL")
	}
	return nil
}

func validateOptionalRequestEmail(raw string) error {
	email := strings.TrimSpace(raw)
	if email == "" {
		return nil
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid unauth request email: %v", err)
	}
	return nil
}

func validateOptionalPortalColor(raw, field string) error {
	color := strings.TrimSpace(raw)
	if color != "" && !isValidServiceLinkColor(color) {
		return fmt.Errorf("%s must be a #RRGGBB value", field)
	}
	return nil
}

func validateServiceLinkEntry(idx int, item AppServiceLink) error {
	if strings.TrimSpace(item.Name) == "" {
		return fmt.Errorf("service link %d name is required", idx+1)
	}
	if len(item.Name) > 64 {
		return fmt.Errorf("service link %d name exceeds 64 characters", idx+1)
	}
	if !isValidPortalLinkURL(item.URL) {
		return fmt.Errorf("service link %d URL must be a relative path or absolute http(s) URL", idx+1)
	}
	if color := strings.TrimSpace(item.Color); color != "" && !isValidServiceLinkColor(color) {
		return fmt.Errorf("service link %d color must be a #RRGGBB value", idx+1)
	}
	return nil
}

func validateAppSettingsConfig(cfg AppSettingsConfig) error {
	if err := validateOptionalPortalLink(cfg.LoginExtraLinkURL); err != nil {
		return err
	}
	if err := validateOptionalRequestEmail(cfg.UnauthRequestEmail); err != nil {
		return err
	}
	if err := validateOptionalPortalColor(cfg.PortalBackgroundColor, "portal background color"); err != nil {
		return err
	}
	if err := validateOptionalPortalColor(cfg.PortalModalColor, "portal modal color"); err != nil {
		return err
	}

	for idx, item := range cfg.ServiceLinks {
		if err := validateServiceLinkEntry(idx, item); err != nil {
			return err
		}
	}
	return nil
}

func normalizeLDAPSyncConfig(cfg *LDAPSyncConfig) {
	defaults := defaultLDAPSyncConfig()
	cfg.LDAPHost = strings.TrimSpace(firstNonEmpty(cfg.LDAPHost, defaults.LDAPHost))
	cfg.LDAPAdminDN = strings.TrimSpace(firstNonEmpty(cfg.LDAPAdminDN, defaults.LDAPAdminDN))
	cfg.LDAPAdminPassword = strings.TrimSpace(firstNonEmpty(cfg.LDAPAdminPassword, defaults.LDAPAdminPassword))
	cfg.BaseDN = strings.TrimSpace(firstNonEmpty(cfg.BaseDN, defaults.BaseDN))
	cfg.ScheduleFrequency = strings.ToLower(strings.TrimSpace(firstNonEmpty(cfg.ScheduleFrequency, defaults.ScheduleFrequency)))
	cfg.ScheduleTimeOfDay = strings.TrimSpace(firstNonEmpty(cfg.ScheduleTimeOfDay, defaults.ScheduleTimeOfDay))
	cfg.ScheduleDayOfWeek = strings.ToLower(strings.TrimSpace(firstNonEmpty(cfg.ScheduleDayOfWeek, defaults.ScheduleDayOfWeek)))
	if cfg.ScheduleMinute < 0 || cfg.ScheduleMinute > 59 {
		cfg.ScheduleMinute = defaults.ScheduleMinute
	}
}

func validateLDAPSyncConfig(cfg LDAPSyncConfig) error {
	if err := ldapsync.ValidateConfig(ldapsync.Config{
		LDAPHost:          cfg.LDAPHost,
		LDAPAdminDN:       cfg.LDAPAdminDN,
		LDAPAdminPassword: cfg.LDAPAdminPassword,
		BaseDN:            cfg.BaseDN,
		LDAPStartTLS:      cfg.LDAPStartTLS,
	}); err != nil {
		return err
	}
	switch cfg.ScheduleFrequency {
	case "hourly", "daily", "weekly":
	default:
		return fmt.Errorf("unsupported ldap sync frequency %q", cfg.ScheduleFrequency)
	}
	if cfg.ScheduleFrequency == "hourly" {
		if cfg.ScheduleMinute < 0 || cfg.ScheduleMinute > 59 {
			return fmt.Errorf("invalid ldap sync minute %d", cfg.ScheduleMinute)
		}
		return nil
	}
	if _, _, err := parseTimeOfDay(cfg.ScheduleTimeOfDay); err != nil {
		return fmt.Errorf("invalid ldap sync time: %w", err)
	}
	if cfg.ScheduleFrequency == "weekly" {
		if _, err := parseWeekday(cfg.ScheduleDayOfWeek); err != nil {
			return fmt.Errorf("invalid ldap sync weekday: %w", err)
		}
	}
	return nil
}

var serviceLinkColorPattern = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func isValidServiceLinkColor(raw string) bool {
	return serviceLinkColorPattern.MatchString(strings.TrimSpace(raw))
}

func isValidPortalLinkURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "http", "https":
		return true
	default:
		return false
	}
}
