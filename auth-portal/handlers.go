package main

import (
	"auth-portal/providers"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	loginTemplate     = "login.html"
	headerContentType = "Content-Type"
	contentTypeJSON   = "application/json"
	signInTitleSuffix = "Sign In"
)

// providerUI returns the provider key used by code ("plex"/"emby")
// and the display name shown in templates.
func providerUI() (key, display string) {
	rc := currentRuntimeConfig()
	key, display = resolveProviderSelection(rc.Providers.Active)
	if key == "" {
		key = mediaProviderKey
	}
	if display == "" {
		display = mediaProviderDisplay
	}
	if key == "" {
		key = activeProvider().Name()
	}
	if key == "" {
		key = "plex"
	}
	if display == "" {
		display = providerCanonicalDisplay(key)
	}
	return
}

// live getters read the current runtime configuration each request.
func extraLink() (urlStr, text string) {
	cfg := currentRuntimeConfig().AppSettings
	return sanitizeDisplayURL(cfg.LoginExtraLinkURL), strings.TrimSpace(cfg.LoginExtraLinkText)
}

type portalServiceButton struct {
	Text               string
	URL                string
	Color              string
	TextColor          string
	RequiredPermission string
}

func serviceButtons(permissions []string) []portalServiceButton {
	cfg := currentRuntimeConfig().AppSettings
	buttons := make([]portalServiceButton, 0, len(cfg.ServiceLinks))
	seen := make(map[string]struct{}, len(cfg.ServiceLinks))
	permissionSet := permissionNameSet(permissions)
	for _, item := range cfg.ServiceLinks {
		button, ok := buildServiceButton(item, permissionSet, seen)
		if !ok {
			continue
		}
		buttons = append(buttons, button)
	}
	return buttons
}

func permissionNameSet(permissions []string) map[string]struct{} {
	out := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		if permission = normalizeRBACName(permission); permission != "" {
			out[permission] = struct{}{}
		}
	}
	return out
}

func buildServiceButton(item AppServiceLink, permissionSet map[string]struct{}, seen map[string]struct{}) (portalServiceButton, bool) {
	safeURL := sanitizeDisplayURL(item.URL)
	safeText := strings.TrimSpace(item.Name)
	if safeURL == "" || safeText == "" {
		return portalServiceButton{}, false
	}
	requiredPermission := normalizeRBACName(item.RequiredPermission)
	if requiredPermission != "" {
		if _, ok := permissionSet[requiredPermission]; !ok {
			return portalServiceButton{}, false
		}
	}
	key := strings.ToLower(safeText) + "|" + safeURL
	if _, exists := seen[key]; exists {
		return portalServiceButton{}, false
	}
	seen[key] = struct{}{}
	safeColor := sanitizeHexColor(item.Color)
	return portalServiceButton{
		Text:               safeText,
		URL:                safeURL,
		Color:              safeColor,
		TextColor:          serviceButtonTextColor(safeColor),
		RequiredPermission: requiredPermission,
	}, true
}

func serviceButtonTextColor(color string) string {
	if color == "" {
		return ""
	}
	return readableTextForHex(color)
}

func portalBackgroundPresentation() (heroColor, modeClass string) {
	heroColor = sanitizeHexColor(currentRuntimeConfig().AppSettings.PortalBackgroundColor)
	if heroColor == "" {
		heroColor = "#0b1020"
	}
	modeClass = "bg-mode-solid"
	return heroColor, modeClass
}

func portalModalPresentation() (cardColor, modeClass string) {
	cardColor = sanitizeHexColor(currentRuntimeConfig().AppSettings.PortalModalColor)
	if cardColor == "" {
		cardColor = "#111827"
	}
	return cardColor, "card-mode-solid"
}

func portalTitleColor() string {
	color := sanitizeHexColor(currentRuntimeConfig().AppSettings.PortalTitleColor)
	if color == "" {
		return "#e5e7eb"
	}
	return color
}

func portalBodyTextColor() string {
	color := sanitizeHexColor(currentRuntimeConfig().AppSettings.PortalBodyTextColor)
	if color == "" {
		return "#94a3b8"
	}
	return color
}

func portalAppName() string {
	name := strings.TrimSpace(currentRuntimeConfig().AppSettings.PortalAppName)
	if name == "" {
		return "AuthPortal"
	}
	return name
}

func portalLogoURL() string {
	logoURL := sanitizeDisplayURL(currentRuntimeConfig().AppSettings.PortalLogoURL)
	if logoURL == "" {
		return "/static/authportal-logo.svg"
	}
	return logoURL
}

func portalFooterEnabled() bool {
	return !currentRuntimeConfig().AppSettings.DisableFooter
}

func portalPageTitle(suffix string) string {
	suffix = strings.TrimSpace(suffix)
	if suffix == "" {
		return portalAppName()
	}
	return portalAppName() + " — " + suffix
}

func renderPortalCopy(raw string, values map[string]string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"{{username}}", values["username"],
		"{{providerName}}", values["providerName"],
		"{{provider}}", values["providerName"],
		"{{appName}}", values["appName"],
	)
	return replacer.Replace(text)
}

func getRequestAccess(providerDisplay string) (email, subj, subjQP string) {
	cfg := currentRuntimeConfig().AppSettings
	email = sanitizeMailAddress(cfg.UnauthRequestEmail)
	if email == "" {
		email = "admin@example.com"
	}
	subj = strings.TrimSpace(cfg.UnauthRequestSubject)
	if subj == "" {
		subj = providerDisplay + " Access Request"
	}
	subjQP = url.QueryEscape(subj)
	return
}

func sanitizeDisplayURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return u.String()
}

func sanitizeHexColor(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) != 7 || !strings.HasPrefix(raw, "#") {
		return ""
	}
	for _, ch := range raw[1:] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return ""
		}
	}
	return strings.ToLower(raw)
}

func readableTextForHex(color string) string {
	color = sanitizeHexColor(color)
	if color == "" {
		return "#e5e7eb"
	}
	rv, _ := strconv.ParseInt(color[1:3], 16, 64)
	gv, _ := strconv.ParseInt(color[3:5], 16, 64)
	bv, _ := strconv.ParseInt(color[5:7], 16, 64)
	luma := (299*rv + 587*gv + 114*bv) / 1000
	if luma >= 140 {
		return "#111827"
	}
	return "#f8fafc"
}

func sanitizeMailAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(addr.Address)
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	key, name := providerUI()
	extraURL, extraText := extraLink()
	heroColor, modeClass := portalBackgroundPresentation()
	cardColor, cardMode := portalModalPresentation()
	titleColor := portalTitleColor()
	bodyTextColor := portalBodyTextColor()
	appName := portalAppName()
	logoURL := portalLogoURL()
	showFooter := portalFooterEnabled()
	loginBodyText := renderPortalCopy(currentRuntimeConfig().AppSettings.LoginBodyText, map[string]string{
		"providerName": name,
		"appName":      appName,
	})

	// If no session, show login page right away.
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		render(w, loginTemplate, map[string]any{
			"BaseURL":             appBaseURL,
			"ProviderKey":         key,
			"ProviderName":        name, // exact casing
			"ExtraLinkURL":        extraURL,
			"ExtraLinkText":       extraText,
			"HeroBackgroundColor": heroColor,
			"HeroBackgroundMode":  modeClass,
			"PortalCardColor":     cardColor,
			"PortalCardMode":      cardMode,
			"PortalTitleColor":    titleColor,
			"PortalBodyTextColor": bodyTextColor,
			"PortalAppName":       appName,
			"PortalLogoURL":       logoURL,
			"PageTitle":           portalPageTitle(signInTitleSuffix),
			"LoginBodyText":       loginBodyText,
			"ShowFooter":          showFooter,
		})
		return
	}

	// Parse JWT to avoid redirecting with an orphaned cookie.
	tok, err := jwt.ParseWithClaims(c.Value, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return sessionSecret, nil
	}, jwt.WithValidMethods(allowedJWTAlgs))
	if err != nil || !tok.Valid {
		clearSessionCookie(w)
		render(w, loginTemplate, map[string]any{
			"BaseURL":             appBaseURL,
			"ProviderKey":         key,
			"ProviderName":        name,
			"ExtraLinkURL":        extraURL,
			"ExtraLinkText":       extraText,
			"HeroBackgroundColor": heroColor,
			"HeroBackgroundMode":  modeClass,
			"PortalCardColor":     cardColor,
			"PortalCardMode":      cardMode,
			"PortalTitleColor":    titleColor,
			"PortalBodyTextColor": bodyTextColor,
			"PortalAppName":       appName,
			"PortalLogoURL":       logoURL,
			"PageTitle":           portalPageTitle(signInTitleSuffix),
			"LoginBodyText":       loginBodyText,
			"ShowFooter":          showFooter,
		})
		return
	}

	claims, ok := tok.Claims.(*sessionClaims)
	if !ok || claims.UUID == "" {
		clearSessionCookie(w)
		render(w, loginTemplate, map[string]any{
			"BaseURL":             appBaseURL,
			"ProviderKey":         key,
			"ProviderName":        name,
			"ExtraLinkURL":        extraURL,
			"ExtraLinkText":       extraText,
			"HeroBackgroundColor": heroColor,
			"HeroBackgroundMode":  modeClass,
			"PortalCardColor":     cardColor,
			"PortalCardMode":      cardMode,
			"PortalTitleColor":    titleColor,
			"PortalBodyTextColor": bodyTextColor,
			"PortalAppName":       appName,
			"PortalLogoURL":       logoURL,
			"PageTitle":           portalPageTitle(signInTitleSuffix),
			"LoginBodyText":       loginBodyText,
			"ShowFooter":          showFooter,
		})
		return
	}

	if _, err := userByUUID(claims.UUID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			clearSessionCookie(w)
			render(w, loginTemplate, map[string]any{
				"BaseURL":             appBaseURL,
				"ProviderKey":         key,
				"ProviderName":        name,
				"ExtraLinkURL":        extraURL,
				"ExtraLinkText":       extraText,
				"HeroBackgroundColor": heroColor,
				"HeroBackgroundMode":  modeClass,
				"PortalCardColor":     cardColor,
				"PortalCardMode":      cardMode,
			})
			return
		}
		log.Printf("login orphan check failed for %s: %v", claims.UUID, err)
		render(w, loginTemplate, map[string]any{
			"BaseURL":             appBaseURL,
			"ProviderKey":         key,
			"ProviderName":        name,
			"ExtraLinkURL":        extraURL,
			"ExtraLinkText":       extraText,
			"HeroBackgroundColor": heroColor,
			"HeroBackgroundMode":  modeClass,
			"PortalCardColor":     cardColor,
			"PortalCardMode":      cardMode,
		})
		return
	}

	http.Redirect(w, r, providers.PostAuthRedirectHome, http.StatusFound)
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	roles, roleErr := userRoles(uuidFrom(r.Context()), usernameFrom(r.Context()))
	if roleErr != nil {
		log.Printf("me: role lookup failed: %v", roleErr)
	}
	permissions, permErr := userPermissions(uuidFrom(r.Context()), usernameFrom(r.Context()))
	if permErr != nil {
		log.Printf("me: permission lookup failed: %v", permErr)
	}
	w.Header().Set(headerContentType, contentTypeJSON)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":    usernameFrom(r.Context()),
		"uuid":        uuidFrom(r.Context()),
		"admin":       adminFrom(r.Context()),
		"roles":       roles,
		"permissions": permissions,
	})
}

// whoamiHandler returns a normalized identity payload for the frontend.
// It is safe to call without an authenticated session; in that case
// it returns authenticated=false along with provider info so the UI can
// render the correct login button.
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	key, display := providerUI()
	out := whoamiResponse{OK: true, Provider: key, ProviderDisplay: display, LoginPath: "/auth/start-web"}

	ident := extractSessionIdentity(r)
	supplementIdentityFromContext(&ident, r.Context())

	if ident.Username == "" && ident.UUID == "" {
		writeWhoamiResponse(w, out)
		return
	}

	populateWhoamiIdentity(&out, ident, r.Context())
	populateWhoamiRoles(&out, ident)
	populateWhoamiAuthorization(&out, ident)
	populateWhoamiEmail(&out, ident.UUID)
	writeWhoamiResponse(w, out)
}

type whoamiResponse struct {
	OK              bool     `json:"ok"`
	Authenticated   bool     `json:"authenticated"`
	Provider        string   `json:"provider"`
	ProviderDisplay string   `json:"providerDisplay"`
	Username        string   `json:"username,omitempty"`
	UUID            string   `json:"uuid,omitempty"`
	Email           string   `json:"email,omitempty"`
	MediaAccess     bool     `json:"mediaAccess"`
	LoginPath       string   `json:"loginPath"`
	IssuedAt        string   `json:"issuedAt,omitempty"`
	Expiry          string   `json:"expiry,omitempty"`
	Admin           bool     `json:"admin"`
	Roles           []string `json:"roles,omitempty"`
	Permissions     []string `json:"permissions,omitempty"`
}

func populateWhoamiIdentity(out *whoamiResponse, ident sessionIdentity, ctx context.Context) {
	out.Authenticated = true
	out.Username = ident.Username
	out.UUID = ident.UUID
	out.IssuedAt = ident.IssuedAt
	out.Expiry = ident.Expiry
	out.Admin = ident.Admin || adminFrom(ctx)
}

func populateWhoamiRoles(out *whoamiResponse, ident sessionIdentity) {
	if roles, err := userRoles(ident.UUID, ident.Username); err == nil {
		out.Roles = roles
	} else {
		log.Printf("whoami role lookup failed for %s (%s): %v", ident.Username, ident.UUID, err)
	}
	if permissions, err := userPermissions(ident.UUID, ident.Username); err == nil {
		out.Permissions = permissions
	} else {
		log.Printf("whoami permission lookup failed for %s (%s): %v", ident.Username, ident.UUID, err)
	}
}

func populateWhoamiAuthorization(out *whoamiResponse, ident sessionIdentity) {
	if authorized, err := activeProvider().IsAuthorized(ident.UUID, ident.Username); err != nil {
		log.Printf("whoami authz check failed for %s (%s): %v", ident.Username, ident.UUID, err)
	} else {
		out.MediaAccess = authorized
	}
}

func populateWhoamiEmail(out *whoamiResponse, uuid string) {
	if uuid == "" {
		return
	}
	u, err := getUserByUUIDPreferred(uuid)
	if err != nil {
		log.Printf("whoami: user lookup failed for %s: %v", uuid, err)
		return
	}
	if u.Email.Valid {
		out.Email = strings.TrimSpace(u.Email.String)
	}
}

func writeWhoamiResponse(w http.ResponseWriter, out whoamiResponse) {
	w.Header().Set(headerContentType, contentTypeJSON)
	_ = json.NewEncoder(w).Encode(out)
}

type sessionIdentity struct {
	Username string
	UUID     string
	Admin    bool
	IssuedAt string
	Expiry   string
}

func extractSessionIdentity(r *http.Request) sessionIdentity {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return sessionIdentity{}
	}
	tok, err := jwt.ParseWithClaims(
		c.Value,
		&sessionClaims{},
		func(t *jwt.Token) (interface{}, error) { return sessionSecret, nil },
		jwt.WithValidMethods(allowedJWTAlgs),
	)
	if err != nil || !tok.Valid {
		return sessionIdentity{}
	}
	claims, ok := tok.Claims.(*sessionClaims)
	if !ok {
		return sessionIdentity{}
	}
	ident := sessionIdentity{
		Username: claims.Username,
		UUID:     claims.UUID,
		Admin:    claims.Admin,
	}
	if claims.IssuedAt != nil {
		ident.IssuedAt = claims.IssuedAt.Time.Format(time.RFC3339)
	}
	if claims.ExpiresAt != nil {
		ident.Expiry = claims.ExpiresAt.Time.Format(time.RFC3339)
	}
	return ident
}

func supplementIdentityFromContext(ident *sessionIdentity, ctx context.Context) {
	if ident.Username == "" && ident.UUID == "" {
		ident.Username = usernameFrom(ctx)
		ident.UUID = uuidFrom(ctx)
	}
	if !ident.Admin {
		ident.Admin = adminFrom(ctx)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	uname := usernameFrom(r.Context())
	uid := uuidFrom(r.Context())

	authorized := false
	var err error
	if uname == "" && uid == "" {
		log.Printf("home: no username/uuid in session; treating as not authorized")
	} else {
		authorized, err = activeProvider().IsAuthorized(uid, uname)
		if err != nil {
			log.Printf("home authz check failed for %s (%s): %v", uname, uid, err)
		}
	}

	// Opportunistic upsert ONLY when authorized (keeps DB lean)
	if authorized {
		if _, err := upsertUser(User{
			Username:    uname,
			MediaUUID:   nullStringFrom(uid),
			MediaAccess: true,
		}); err != nil {
			log.Printf("home: upsert user failed for %s (%s): %v", uname, uid, err)
		}
	}

	// Use env-cased name for display
	_, providerDisplay := providerUI()
	extraURL, extraText := extraLink()
	heroColor, modeClass := portalBackgroundPresentation()
	cardColor, cardMode := portalModalPresentation()
	titleColor := portalTitleColor()
	bodyTextColor := portalBodyTextColor()
	appName := portalAppName()
	logoURL := portalLogoURL()
	showFooter := portalFooterEnabled()

	if authorized {
		permissions, permErr := userPermissions(uid, uname)
		if permErr != nil {
			log.Printf("home: permission lookup failed for %s (%s): %v", uname, uid, permErr)
		}
		serviceLinks := serviceButtons(permissions)
		copyValues := map[string]string{
			"username":     uname,
			"providerName": providerDisplay,
			"appName":      appName,
		}
		render(w, "portal_authorized.html", map[string]any{
			"Username":            uname,
			"ProviderName":        providerDisplay, // exact casing
			"ExtraLinkURL":        extraURL,
			"ExtraLinkText":       extraText,
			"ServiceLinks":        serviceLinks,
			"HeroBackgroundColor": heroColor,
			"HeroBackgroundMode":  modeClass,
			"PortalCardColor":     cardColor,
			"PortalCardMode":      cardMode,
			"PortalTitleColor":    titleColor,
			"PortalBodyTextColor": bodyTextColor,
			"PortalAppName":       appName,
			"PortalLogoURL":       logoURL,
			"PageTitle":           portalPageTitle("Authorized"),
			"WelcomeTitle":        renderPortalCopy(currentRuntimeConfig().AppSettings.AuthorizedTitleText, copyValues),
			"BodyText":            renderPortalCopy(currentRuntimeConfig().AppSettings.AuthorizedBodyText, copyValues),
			"ShowFooter":          showFooter,
		})
		return
	}

	// Unauthorized page: build mailto params from env
	email, subj, subjQP := getRequestAccess(providerDisplay)
	copyValues := map[string]string{
		"username":     uname,
		"providerName": providerDisplay,
		"appName":      appName,
	}
	render(w, "portal_unauthorized.html", map[string]any{
		"Username":            uname,
		"ProviderName":        providerDisplay, // exact casing
		"RequestEmail":        email,
		"RequestSubject":      subj,
		"RequestSubjectQP":    subjQP,
		"HeroBackgroundColor": heroColor,
		"HeroBackgroundMode":  modeClass,
		"PortalCardColor":     cardColor,
		"PortalCardMode":      cardMode,
		"PortalTitleColor":    titleColor,
		"PortalBodyTextColor": bodyTextColor,
		"PortalAppName":       appName,
		"PortalLogoURL":       logoURL,
		"PageTitle":           portalPageTitle("Access Pending"),
		"WelcomeTitle":        renderPortalCopy(currentRuntimeConfig().AppSettings.UnauthorizedTitleText, copyValues),
		"BodyText":            renderPortalCopy(currentRuntimeConfig().AppSettings.UnauthorizedBodyText, copyValues),
		"ShowFooter":          showFooter,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func mfaChallengePage(w http.ResponseWriter, r *http.Request) {
	claims, err := pendingClaimsFromRequest(r)
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			clearPendingMFACookie(w)
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if mfaEnforceForAllUsers {
		enabled, checkErr := userHasMFAEnabled(claims.UUID, claims.Username)
		if checkErr != nil {
			log.Printf("mfa challenge: enforcement lookup failed for %s (%s): %v", strings.TrimSpace(claims.Username), strings.TrimSpace(claims.UUID), checkErr)
		} else if !enabled {
			http.Redirect(w, r, "/mfa/enroll?pending=1", http.StatusFound)
			return
		}
	}

	heroColor, heroMode := portalBackgroundPresentation()
	cardColor, cardMode := portalModalPresentation()
	render(w, "mfa_challenge.html", map[string]any{
		"Username":            strings.TrimSpace(claims.Username),
		"Issuer":              mfaIssuer,
		"HeroBackgroundColor": heroColor,
		"HeroBackgroundMode":  heroMode,
		"PortalCardColor":     cardColor,
		"PortalCardMode":      cardMode,
	})
}
func mfaEnrollPage(w http.ResponseWriter, r *http.Request) {
	uname := strings.TrimSpace(usernameFrom(r.Context()))
	if uname == "" {
		http.Redirect(w, r, providers.PostAuthRedirectHome, http.StatusFound)
		return
	}
	heroColor, heroMode := portalBackgroundPresentation()
	cardColor, cardMode := portalModalPresentation()
	render(w, "mfa_enroll.html", map[string]any{
		"Username":            uname,
		"Issuer":              mfaIssuer,
		"HeroBackgroundColor": heroColor,
		"HeroBackgroundMode":  heroMode,
		"PortalCardColor":     cardColor,
		"PortalCardMode":      cardMode,
	})
}
