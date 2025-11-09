package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"auth-portal/configstore"
)

// ProvidersConfig models provider-specific runtime configuration.
type ProvidersConfig struct {
	Active string `json:"active"`

	Plex struct {
		OwnerToken      string `json:"ownerToken"`
		ServerMachineID string `json:"serverMachineId"`
		ServerName      string `json:"serverName"`
	} `json:"plex"`

	Emby struct {
		ServerURL     string `json:"serverUrl"`
		AppName       string `json:"appName"`
		AppVersion    string `json:"appVersion"`
		APIKey        string `json:"apiKey"`
		OwnerUsername string `json:"ownerUsername"`
		OwnerID       string `json:"ownerId"`
	} `json:"emby"`

	Jellyfin struct {
		ServerURL  string `json:"serverUrl"`
		AppName    string `json:"appName"`
		AppVersion string `json:"appVersion"`
		APIKey     string `json:"apiKey"`
	} `json:"jellyfin"`
}

// SecurityConfig captures session/security-centric runtime controls.
type SecurityConfig struct {
	SessionTTL          string `json:"sessionTtl"`
	SessionSameSite     string `json:"sessionSameSite"`
	ForceSecureCookie   bool   `json:"forceSecureCookie"`
	SessionCookieDomain string `json:"sessionCookieDomain"`
}

// MFAConfig groups MFA feature toggles.
type MFAConfig struct {
	Issuer             string `json:"issuer"`
	EnrollmentEnabled  bool   `json:"enrollmentEnabled"`
	EnforceForAllUsers bool   `json:"enforceForAllUsers"`
}

// AppSettingsConfig captures miscellaneous portal presentation controls.
type AppSettingsConfig struct {
	LoginExtraLinkURL    string `json:"loginExtraLinkUrl"`
	LoginExtraLinkText   string `json:"loginExtraLinkText"`
	UnauthRequestEmail   string `json:"unauthRequestEmail"`
	UnauthRequestSubject string `json:"unauthRequestSubject"`
}

// RuntimeConfig represents all typed configuration sections with revision metadata.
type RuntimeConfig struct {
	Providers        ProvidersConfig
	ProvidersVersion int64

	Security        SecurityConfig
	SecurityVersion int64

	MFA        MFAConfig
	MFAVersion int64

	AppSettings        AppSettingsConfig
	AppSettingsVersion int64

	LoadedAt time.Time
}

var runtimeConfigValue atomic.Value

func runtimeConfigDefaults() (map[configstore.Section]json.RawMessage, error) {
	defaults := make(map[configstore.Section]json.RawMessage, 4)

	if raw, err := json.Marshal(defaultProvidersConfig()); err != nil {
		return nil, err
	} else {
		defaults[configstore.SectionProviders] = raw
	}

	if raw, err := json.Marshal(defaultSecurityConfig()); err != nil {
		return nil, err
	} else {
		defaults[configstore.SectionSecurity] = raw
	}

	if raw, err := json.Marshal(defaultMFAConfig()); err != nil {
		return nil, err
	} else {
		defaults[configstore.SectionMFA] = raw
	}

	if raw, err := json.Marshal(defaultAppSettingsConfig()); err != nil {
		return nil, err
	} else {
		defaults[configstore.SectionAppSettings] = raw
	}

	return defaults, nil
}

func defaultProvidersConfig() ProvidersConfig {
	cfg := ProvidersConfig{
		Active: strings.TrimSpace(os.Getenv("MEDIA_SERVER")),
	}
	if cfg.Active == "" {
		cfg.Active = "plex"
	}

	cfg.Plex.OwnerToken = envOr("PLEX_OWNER_TOKEN", "")
	cfg.Plex.ServerMachineID = envOr("PLEX_SERVER_MACHINE_ID", "")
	cfg.Plex.ServerName = envOr("PLEX_SERVER_NAME", "")

	cfg.Emby.ServerURL = envOr("EMBY_SERVER_URL", "http://localhost:8096")
	cfg.Emby.AppName = envOr("EMBY_APP_NAME", "AuthPortal")
	cfg.Emby.AppVersion = envOr("EMBY_APP_VERSION", "2.0.0")
	cfg.Emby.APIKey = envOr("EMBY_API_KEY", "")
	cfg.Emby.OwnerUsername = envOr("EMBY_OWNER_USERNAME", "")
	cfg.Emby.OwnerID = envOr("EMBY_OWNER_ID", "")

	cfg.Jellyfin.ServerURL = envOr("JELLYFIN_SERVER_URL", "http://localhost:8096")
	cfg.Jellyfin.AppName = envOr("JELLYFIN_APP_NAME", "AuthPortal")
	cfg.Jellyfin.AppVersion = envOr("JELLYFIN_APP_VERSION", "2.0.0")
	cfg.Jellyfin.APIKey = envOr("JELLYFIN_API_KEY", "")

	return cfg
}

func defaultSecurityConfig() SecurityConfig {
	cfg := SecurityConfig{
		SessionTTL:          strings.TrimSpace(os.Getenv("SESSION_TTL")),
		SessionSameSite:     strings.TrimSpace(strings.ToLower(os.Getenv("SESSION_SAMESITE"))),
		ForceSecureCookie:   envBool("FORCE_SECURE_COOKIE", false),
		SessionCookieDomain: strings.TrimSpace(os.Getenv("SESSION_COOKIE_DOMAIN")),
	}
	if cfg.SessionTTL == "" {
		cfg.SessionTTL = "24h"
	}
	if cfg.SessionSameSite == "" {
		cfg.SessionSameSite = "lax"
	}
	return cfg
}

func defaultMFAConfig() MFAConfig {
	return MFAConfig{
		Issuer:             envOr("MFA_ISSUER", "AuthPortal"),
		EnrollmentEnabled:  envBool("MFA_ENABLE", true),
		EnforceForAllUsers: envBool("MFA_ENFORCE", false),
	}
}

func defaultAppSettingsConfig() AppSettingsConfig {
	cfg := AppSettingsConfig{
		LoginExtraLinkURL:    strings.TrimSpace(os.Getenv("LOGIN_EXTRA_LINK_URL")),
		LoginExtraLinkText:   strings.TrimSpace(os.Getenv("LOGIN_EXTRA_LINK_TEXT")),
		UnauthRequestEmail:   strings.TrimSpace(os.Getenv("UNAUTH_REQUEST_EMAIL")),
		UnauthRequestSubject: strings.TrimSpace(os.Getenv("UNAUTH_REQUEST_SUBJECT")),
	}

	if cfg.LoginExtraLinkURL == "" {
		cfg.LoginExtraLinkURL = "/some-internal-app"
	}
	if cfg.LoginExtraLinkText == "" {
		cfg.LoginExtraLinkText = "Open Internal App"
	}
	if cfg.UnauthRequestEmail == "" {
		cfg.UnauthRequestEmail = "admin@example.com"
	}
	if cfg.UnauthRequestSubject == "" {
		cfg.UnauthRequestSubject = "Request Access"
	}
	return cfg
}

func loadRuntimeConfig(store *configstore.Store) (RuntimeConfig, error) {
	return loadRuntimeConfigInternal(store, false)
}

func loadRuntimeConfigInternal(store *configstore.Store, retried bool) (RuntimeConfig, error) {
	if store == nil {
		return RuntimeConfig{}, errors.New("configstore: store is nil")
	}

	var (
		rc RuntimeConfig
	)

	var providers ProvidersConfig
	pVersion, err := store.Section(configstore.SectionProviders, &providers)
	if err != nil {
		return RuntimeConfig{}, err
	}

	var security SecurityConfig
	sVersion, err := store.Section(configstore.SectionSecurity, &security)
	if err != nil {
		return RuntimeConfig{}, err
	}

	var mfa MFAConfig
	mVersion, err := store.Section(configstore.SectionMFA, &mfa)
	if err != nil {
		return RuntimeConfig{}, err
	}

	var app AppSettingsConfig
	aVersion, err := store.Section(configstore.SectionAppSettings, &app)
	if err != nil {
		return RuntimeConfig{}, err
	}

	rc.Providers = providers
	rc.ProvidersVersion = pVersion
	rc.Security = security
	rc.SecurityVersion = sVersion
	rc.MFA = mfa
	rc.MFAVersion = mVersion
	rc.AppSettings = app
	rc.AppSettingsVersion = aVersion

	snap := store.Snapshot()
	if !snap.LoadedAt.IsZero() {
		rc.LoadedAt = snap.LoadedAt
	} else {
		rc.LoadedAt = time.Now().UTC()
	}

	missing := detectMissingSections(pVersion, sVersion, mVersion, aVersion)
	if len(missing) > 0 && !retried {
		if err := persistInitialSections(store, rc, missing); err != nil {
			return RuntimeConfig{}, err
		}
		return loadRuntimeConfigInternal(store, true)
	}

	return rc, nil
}

func applyRuntimeConfig(cfg RuntimeConfig) {
	defaults := RuntimeConfig{
		Providers:   defaultProvidersConfig(),
		Security:    defaultSecurityConfig(),
		MFA:         defaultMFAConfig(),
		AppSettings: defaultAppSettingsConfig(),
	}

	selectedProvider := strings.TrimSpace(cfg.Providers.Active)
	if selectedProvider == "" {
		selectedProvider = defaults.Providers.Active
	}
	mediaServerSelection = selectedProvider
	mediaProviderKey, mediaProviderDisplay = resolveProviderSelection(mediaServerSelection)
	cfg.Providers.Active = mediaServerSelection

	plexOwnerToken = strings.TrimSpace(firstNonEmpty(cfg.Providers.Plex.OwnerToken, defaults.Providers.Plex.OwnerToken))
	cfg.Providers.Plex.OwnerToken = plexOwnerToken
	plexServerMachineID = strings.TrimSpace(firstNonEmpty(cfg.Providers.Plex.ServerMachineID, defaults.Providers.Plex.ServerMachineID))
	cfg.Providers.Plex.ServerMachineID = plexServerMachineID
	plexServerName = strings.TrimSpace(firstNonEmpty(cfg.Providers.Plex.ServerName, defaults.Providers.Plex.ServerName))
	cfg.Providers.Plex.ServerName = plexServerName

	embyServerURL = strings.TrimSpace(firstNonEmpty(cfg.Providers.Emby.ServerURL, defaults.Providers.Emby.ServerURL))
	cfg.Providers.Emby.ServerURL = embyServerURL
	embyAppName = strings.TrimSpace(firstNonEmpty(cfg.Providers.Emby.AppName, defaults.Providers.Emby.AppName))
	cfg.Providers.Emby.AppName = embyAppName
	embyAppVersion = strings.TrimSpace(firstNonEmpty(cfg.Providers.Emby.AppVersion, defaults.Providers.Emby.AppVersion))
	cfg.Providers.Emby.AppVersion = embyAppVersion
	embyAPIKey = strings.TrimSpace(firstNonEmpty(cfg.Providers.Emby.APIKey, defaults.Providers.Emby.APIKey))
	cfg.Providers.Emby.APIKey = embyAPIKey
	embyOwnerUsername = strings.TrimSpace(firstNonEmpty(cfg.Providers.Emby.OwnerUsername, defaults.Providers.Emby.OwnerUsername))
	cfg.Providers.Emby.OwnerUsername = embyOwnerUsername
	embyOwnerID = strings.TrimSpace(firstNonEmpty(cfg.Providers.Emby.OwnerID, defaults.Providers.Emby.OwnerID))
	cfg.Providers.Emby.OwnerID = embyOwnerID

	jellyfinServerURL = strings.TrimSpace(firstNonEmpty(cfg.Providers.Jellyfin.ServerURL, defaults.Providers.Jellyfin.ServerURL))
	cfg.Providers.Jellyfin.ServerURL = jellyfinServerURL
	jellyfinAppName = strings.TrimSpace(firstNonEmpty(cfg.Providers.Jellyfin.AppName, defaults.Providers.Jellyfin.AppName))
	cfg.Providers.Jellyfin.AppName = jellyfinAppName
	jellyfinAppVersion = strings.TrimSpace(firstNonEmpty(cfg.Providers.Jellyfin.AppVersion, defaults.Providers.Jellyfin.AppVersion))
	cfg.Providers.Jellyfin.AppVersion = jellyfinAppVersion
	jellyfinAPIKey = strings.TrimSpace(firstNonEmpty(cfg.Providers.Jellyfin.APIKey, defaults.Providers.Jellyfin.APIKey))
	cfg.Providers.Jellyfin.APIKey = jellyfinAPIKey

	ttlInput := strings.TrimSpace(firstNonEmpty(cfg.Security.SessionTTL, defaults.Security.SessionTTL))
	cfg.Security.SessionTTL = ttlInput
	sessionTTL = parseDurationOr(ttlInput, parseDurationOr(defaults.Security.SessionTTL, 24*time.Hour))
	if sessionTTL <= 0 {
		log.Printf("Invalid session TTL %q; defaulting to 24h", ttlInput)
		sessionTTL = 24 * time.Hour
	}

	sameSiteInput := strings.TrimSpace(firstNonEmpty(cfg.Security.SessionSameSite, defaults.Security.SessionSameSite))
	cfg.Security.SessionSameSite = sameSiteInput
	sessionSameSite = parseSameSite(sameSiteInput, http.SameSiteLaxMode)
	forceSecureCookie = cfg.Security.ForceSecureCookie
	sessionCookieDomain = strings.TrimSpace(firstNonEmpty(cfg.Security.SessionCookieDomain, defaults.Security.SessionCookieDomain))
	cfg.Security.SessionCookieDomain = sessionCookieDomain
	sessionSameSiteWarningLogged = false

	mfaIssuer = strings.TrimSpace(firstNonEmpty(cfg.MFA.Issuer, defaults.MFA.Issuer))
	cfg.MFA.Issuer = mfaIssuer
	mfaEnrollmentEnabled = cfg.MFA.EnrollmentEnabled
	mfaEnforceForAllUsers = cfg.MFA.EnforceForAllUsers
	ensureMFAConsistency()

	loginExtraLinkURL = strings.TrimSpace(firstNonEmpty(cfg.AppSettings.LoginExtraLinkURL, defaults.AppSettings.LoginExtraLinkURL))
	cfg.AppSettings.LoginExtraLinkURL = loginExtraLinkURL
	loginExtraLinkText = strings.TrimSpace(firstNonEmpty(cfg.AppSettings.LoginExtraLinkText, defaults.AppSettings.LoginExtraLinkText))
	cfg.AppSettings.LoginExtraLinkText = loginExtraLinkText
	unauthRequestEmail = strings.TrimSpace(firstNonEmpty(cfg.AppSettings.UnauthRequestEmail, defaults.AppSettings.UnauthRequestEmail))
	cfg.AppSettings.UnauthRequestEmail = unauthRequestEmail
	unauthRequestSubject = strings.TrimSpace(firstNonEmpty(cfg.AppSettings.UnauthRequestSubject, defaults.AppSettings.UnauthRequestSubject))
	if unauthRequestSubject == "" {
		unauthRequestSubject = defaults.AppSettings.UnauthRequestSubject
	}
	cfg.AppSettings.UnauthRequestSubject = unauthRequestSubject

	if cfg.LoadedAt.IsZero() {
		cfg.LoadedAt = time.Now().UTC()
	}
	runtimeConfigValue.Store(cfg)
}

func currentRuntimeConfig() RuntimeConfig {
	if v := runtimeConfigValue.Load(); v != nil {
		if cfg, ok := v.(RuntimeConfig); ok {
			return cfg
		}
	}
	return RuntimeConfig{
		Providers:   defaultProvidersConfig(),
		Security:    defaultSecurityConfig(),
		MFA:         defaultMFAConfig(),
		AppSettings: defaultAppSettingsConfig(),
		LoadedAt:    time.Now().UTC(),
	}
}

func (rc RuntimeConfig) loadedAt() time.Time {
	if rc.LoadedAt.IsZero() {
		return time.Now().UTC()
	}
	return rc.LoadedAt
}

func resolveProviderSelection(raw string) (key, display string) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	switch lower {
	case "", "plex":
		return "plex", providerCanonicalDisplay("plex")
	case "emby", "emby-connect", "embyconnect", "emby_connect":
		return "emby", providerCanonicalDisplay("emby")
	case "jellyfin":
		return "jellyfin", providerCanonicalDisplay("jellyfin")
	default:
		if trimmed == "" {
			return "plex", providerCanonicalDisplay("plex")
		}
		return lower, trimmed
	}
}

func providerCanonicalDisplay(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "emby":
		return "Emby"
	case "jellyfin":
		return "Jellyfin"
	default:
		return "Plex"
	}
}

func ensureMFAConsistency() {
	if mfaEnforceForAllUsers && !mfaEnrollmentEnabled {
		log.Println("MFA enforcement enabled but enrollment disabled; enabling enrollment so enforcement can proceed")
		mfaEnrollmentEnabled = true
	}
}

func detectMissingSections(pVersion, sVersion, mVersion, aVersion int64) []configstore.Section {
	var sections []configstore.Section
	if pVersion == 0 {
		sections = append(sections, configstore.SectionProviders)
	}
	if sVersion == 0 {
		sections = append(sections, configstore.SectionSecurity)
	}
	if mVersion == 0 {
		sections = append(sections, configstore.SectionMFA)
	}
	if aVersion == 0 {
		sections = append(sections, configstore.SectionAppSettings)
	}
	return sections
}

func persistInitialSections(store *configstore.Store, cfg RuntimeConfig, sections []configstore.Section) error {
	ctx := context.Background()
	for _, section := range sections {
		var payload any
		switch section {
		case configstore.SectionProviders:
			payload = cfg.Providers
		case configstore.SectionSecurity:
			payload = cfg.Security
		case configstore.SectionMFA:
			payload = cfg.MFA
		case configstore.SectionAppSettings:
			payload = cfg.AppSettings
		default:
			continue
		}

		if _, err := store.UpsertSection(ctx, section, payload, configstore.UpdateOptions{
			UpdatedBy: "system:bootstrap",
			Reason:    "initial default config",
		}); err != nil {
			return err
		}
	}
	return nil
}
