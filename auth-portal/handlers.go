package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Use the same client identifier you used before
var plexClientID = "auth-portal-go"

// -------- Shared structs you already use --------

type PinResponse struct {
	ID               int    `json:"id"`
	Code             string `json:"code"`
	AuthToken        string `json:"authToken"`
	ClientIdentifier string `json:"clientIdentifier"`
	QR               string `json:"qr"`
	ExpiresIn        int    `json:"expiresIn"`
	CreatedAt        string `json:"createdAt"`
	ExpiresAt        string `json:"expiresAt"`
}

type TokenResponse struct {
	AuthToken string `json:"authToken"`
	User      struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		UUID     string `json:"uuid"`
	} `json:"user"`
}

// ---------------------- Login (web popup) ----------------------

// POST /auth/start-web
func startAuthWebHandler(w http.ResponseWriter, r *http.Request) {
	// Create strong PIN (JSON)
	req, err := http.NewRequest("POST", "https://plex.tv/api/v2/pins?strong=true", nil)
	if err != nil {
		http.Error(w, "request init failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Client-Identifier", plexClientID)
	req.Header.Set("X-Plex-Version", "1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "plex unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		http.Error(w, "plex PIN create failed", http.StatusBadGateway)
		return
	}

	var pin struct {
		ID   int    `json:"id"`
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pin); err != nil {
		http.Error(w, "plex decode failed", http.StatusBadGateway)
		return
	}

	// Persist mapping code→id so we can look it up later
	_ = savePin(pin.Code, pin.ID)

	// Build the Plex Auth App URL that opens in the popup
	forward := appBaseURL + "/auth/forward?pinId=" + url.QueryEscape(strconv.Itoa(pin.ID)) +
		"&code=" + url.QueryEscape(pin.Code)

	q := url.Values{}
	q.Set("clientID", plexClientID)
	q.Set("code", pin.Code)
	q.Set("forwardUrl", forward)
	q.Set("context[device][product]", "AuthPortal")

	authURL := "https://app.plex.tv/auth#?" + q.Encode()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"authUrl": authURL})
}

// GET /auth/forward
func forwardHandler(w http.ResponseWriter, r *http.Request) {
	pinIDStr := r.URL.Query().Get("pinId")
	code := r.URL.Query().Get("code")
	if pinIDStr == "" || code == "" {
		http.Error(w, "missing params", http.StatusBadRequest)
		return
	}
	pinID, err := strconv.Atoi(pinIDStr)
	if err != nil {
		http.Error(w, "bad pinId", http.StatusBadRequest)
		return
	}

	// Poll quickly for the token
	var tokenResp struct{ AuthToken string `json:"authToken"` }
	ok := false
	for i := 0; i < 6; i++ { // ~9 seconds total
		reqURL := fmt.Sprintf("https://plex.tv/api/v2/pins/%d?code=%s", pinID, url.QueryEscape(code))
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Plex-Client-Identifier", plexClientID)

		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&tokenResp)
			resp.Body.Close()
			if tokenResp.AuthToken != "" {
				ok = true
				break
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1500 * time.Millisecond)
	}

	if ok {
		// Fetch profile, decide authz, only persist if authorized; always set session cookie
		profile, perr := fetchUserProfile(tokenResp.AuthToken)
		if perr == nil {
			// 1) Check authorization first
			authorized := false
			if okAuth, err := isUserAuthorizedOnServer(profile.User.UUID, profile.User.Username); err == nil {
				authorized = okAuth
			} else {
				log.Printf("authz check failed after login for %s (%s): %v", profile.User.Username, profile.User.UUID, err)
			}

			// 2) Persist ONLY authorized users
			if authorized {
				if _, err := upsertUser(User{
					Username:   profile.User.Username,
					Email:      nullStringFrom(profile.User.Email),
					PlexUUID:   nullStringFrom(profile.User.UUID),
					PlexToken:  nullStringFrom(tokenResp.AuthToken),
					PlexAccess: true,
				}); err != nil {
					log.Printf("upsertUser error (authorized): %v", err)
				}
				if err := setSessionCookie(w, profile.User.UUID, profile.User.Username); err != nil {
					log.Printf("setSessionCookie error: %v", err)
				}
			} else {
				log.Printf("skipping DB persist for unauthorized user %q (%s)", profile.User.Username, profile.User.UUID)
			}

			// 3) Issue session cookie so the opener can be routed to /home and see the proper page
			if err := setTempSessionCookie(w, profile.User.UUID, profile.User.Username); err != nil {
				log.Printf("setTempSessionCookie error: %v", err)
			}
		} else {
			ok = false
		}
	}

	// Tiny page to notify opener and close; relax CSP ONLY for this response.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
	dest := appBaseURL + "/home"

	fmt.Fprintf(w, `<!doctype html>
<meta charset="utf-8">
<title>AuthPortal</title>
<script>
(function(){
  var ok = %v;
  var dest = %q;
  try {
    if (window.opener && window.opener !== window) {
      try { window.opener.postMessage({type:"auth-portal", ok: ok}, window.location.origin); } catch(e){}
      if (ok) { try { window.opener.location = dest; } catch(e){} }
    }
  } catch(e){}
  setTimeout(function(){ window.close(); }, 200);
})();
</script>
<body style="background:#0b1020;color:#e5e7eb;font:14px system-ui">
  <p style="text-align:center;margin-top:20vh">You can close this window.</p>
</body>`, ok, dest)
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
    if hasValidSession(r) {
        http.Redirect(w, r, "/home", http.StatusFound)
        return
    }
    render(w, "login.html", map[string]any{"BaseURL": appBaseURL})
}

// ---------- Account profile (JSON) ----------

type accountResponse struct {
	User struct {
		ID       int    `json:"id"`
		UUID     string `json:"uuid"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	AuthToken string `json:"-"`
}

func fetchUserProfile(authToken string) (accountResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://plex.tv/users/account.json", nil)
	req.Header.Set("X-Plex-Token", authToken)
	req.Header.Set("X-Plex-Product", "AuthPortal")
	req.Header.Set("X-Plex-Version", "1.0")
	req.Header.Set("X-Plex-Client-Identifier", "auth-portal-go")
	req.Header.Set("X-Plex-Device", "Server")
	req.Header.Set("X-Plex-Platform", "Docker")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return accountResponse{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return accountResponse{}, fmt.Errorf("Plex API returned %d: %s", resp.StatusCode, string(body))
	}
	if len(body) > 0 && body[0] == '<' {
		return accountResponse{}, fmt.Errorf("expected JSON but got XML/HTML: %.120s", string(body))
	}

	var profile accountResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return accountResponse{}, fmt.Errorf("JSON decode failed: %w; body: %s", err, string(body))
	}
	profile.AuthToken = authToken
	return profile, nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---------------- Plex authorization (owner token required) ----------------

type deviceList struct {
	XMLName xml.Name `xml:"MediaContainer"`
	Devices []device `xml:"Device"`
}
type device struct {
	Name             string `xml:"name,attr"`
	Provides         string `xml:"provides,attr"`
	ClientIdentifier string `xml:"clientIdentifier,attr"` // machine identifier
	Product          string `xml:"product,attr"`
}

var cachedMachineID string
var cachedMachineIDTime time.Time

// resolvePlexServerMachineID finds the target PMS machine id using owner token.
// Priority: env PLEX_SERVER_MACHINE_ID → resolve by PLEX_SERVER_NAME → first PMS found.
func resolvePlexServerMachineID() (string, error) {
	if plexOwnerToken == "" {
		return "", fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}
	if plexServerMachineID != "" {
		return plexServerMachineID, nil
	}
	// small cache (~10 minutes) to avoid hammering Plex
	if cachedMachineID != "" && time.Since(cachedMachineIDTime) < 10*time.Minute {
		return cachedMachineID, nil
	}

	req, _ := http.NewRequest("GET", "https://plex.tv/api/resources?includeHttps=1", nil)
	req.Header.Set("X-Plex-Token", plexOwnerToken)
	req.Header.Set("Accept", "application/xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resources request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("resources returned %d: %s", resp.StatusCode, string(b))
	}
	var dl deviceList
	if err := xml.NewDecoder(resp.Body).Decode(&dl); err != nil {
		return "", fmt.Errorf("resources xml decode: %w", err)
	}
	// Find PMS
	var first string
	for _, d := range dl.Devices {
		if !strings.Contains(d.Provides, "server") && d.Product != "Plex Media Server" {
			continue
		}
		if first == "" {
			first = d.ClientIdentifier
		}
		if plexServerName != "" && d.Name == plexServerName {
			cachedMachineID = d.ClientIdentifier
			cachedMachineIDTime = time.Now()
			return cachedMachineID, nil
		}
	}
	if first == "" {
		return "", fmt.Errorf("no Plex Media Server device found on owner account")
	}
	cachedMachineID = first
	cachedMachineIDTime = time.Now()
	return cachedMachineID, nil
}

// /api/servers/{machineId}/shared_servers returns <SharedServer ...> entries
type sharedServersDoc struct {
	XMLName       xml.Name            `xml:"MediaContainer"`
	SharedServers []sharedServerEntry `xml:"SharedServer"`
}

type sharedServerEntry struct {
	ID       int    `xml:"id,attr"`       // shared record id
	Username string `xml:"username,attr"` // the user's Plex username
	Email    string `xml:"email,attr"`    // email (if available)
	UserID   int    `xml:"userID,attr"`   // numeric user id (not UUID)
	Owned    int    `xml:"owned,attr"`    // 1 if this user owns the server (for owner)
	// ... plus many library <Section> children we don't need for auth check
}

// cache the shared-servers response for a short period
var (
	sharedCacheMu sync.Mutex
	sharedCache   = struct {
		machineID string
		fetched   time.Time
		entries   []sharedServerEntry
	}{}
)

// --- Owner identity (from PLEX_OWNER_TOKEN), cached to avoid refetching ---

type ownerAccount struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
}

var (
	ownerCache     ownerAccount
	ownerCacheTime time.Time
)

func fetchOwnerIdentity() (ownerAccount, error) {
	if plexOwnerToken == "" {
		return ownerAccount{}, fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}
	// cache for 10 minutes
	if time.Since(ownerCacheTime) < 10*time.Minute && ownerCache.UUID != "" {
		return ownerCache, nil
	}

	req, _ := http.NewRequest("GET", "https://plex.tv/users/account.json", nil)
	req.Header.Set("X-Plex-Token", plexOwnerToken)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ownerAccount{}, fmt.Errorf("owner /users/account.json failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return ownerAccount{}, fmt.Errorf("owner account returned %d: %s", resp.StatusCode, string(body))
	}

	// Reuse accountResponse shape
	var acc accountResponse
	if err := json.Unmarshal(body, &acc); err != nil {
		return ownerAccount{}, fmt.Errorf("owner account decode: %w", err)
	}
	ownerCache = ownerAccount{
		UUID:     strings.TrimSpace(acc.User.UUID),
		Username: strings.TrimSpace(acc.User.Username),
	}
	ownerCacheTime = time.Now()
	return ownerCache, nil
}

func fetchSharedServers(machineID string) ([]sharedServerEntry, error) {
	// cache for 5 minutes
	sharedCacheMu.Lock()
	if sharedCache.machineID == machineID && time.Since(sharedCache.fetched) < 5*time.Minute {
		entries := sharedCache.entries
		sharedCacheMu.Unlock()
		return entries, nil
	}
	sharedCacheMu.Unlock()

	url := fmt.Sprintf("https://plex.tv/api/servers/%s/shared_servers", machineID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Plex-Token", plexOwnerToken)
	req.Header.Set("Accept", "application/xml")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shared_servers request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shared_servers returned %d: %s", resp.StatusCode, string(b))
	}

	var doc sharedServersDoc
	if err := xml.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("shared_servers xml decode: %w", err)
	}

	sharedCacheMu.Lock()
	sharedCache.machineID = machineID
	sharedCache.fetched = time.Now()
	sharedCache.entries = doc.SharedServers
	sharedCacheMu.Unlock()

	return doc.SharedServers, nil
}

// -------- Plex Home users (owner token) --------

type homeUsers struct {
	Users []homeUser `xml:"User"`
}
type homeUser struct {
	ID       int    `xml:"id,attr"`
	UUID     string `xml:"uuid,attr"`
	Username string `xml:"username,attr"`
}

// fetchHomeUsers returns the list of users in the owner’s Plex Home.
// Requires PLEX_OWNER_TOKEN.
func fetchHomeUsers() ([]homeUser, error) {
	if plexOwnerToken == "" {
		return nil, fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}
	req, _ := http.NewRequest("GET", "https://plex.tv/api/home/users", nil)
	req.Header.Set("X-Plex-Token", plexOwnerToken)
	req.Header.Set("Accept", "application/xml")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("home users request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("home users returned %d: %s", resp.StatusCode, string(b))
	}

	var hu homeUsers
	if err := xml.NewDecoder(resp.Body).Decode(&hu); err != nil {
		return nil, fmt.Errorf("home users xml decode: %w", err)
	}
	return hu.Users, nil
}

// isUserAuthorizedOnServer returns true if the Plex UUID (preferred) or username has access.
// Order: owner → server's SharedServer entries → Plex Home users
func isUserAuthorizedOnServer(userUUID string, username string) (bool, error) {
	if plexOwnerToken == "" {
		return false, fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}

	// Owner short-circuit (owners don't appear in shared lists)
	if owner, err := fetchOwnerIdentity(); err == nil {
		if (userUUID != "" && strings.EqualFold(userUUID, owner.UUID)) ||
			(username != "" && strings.EqualFold(username, owner.Username)) {
			return true, nil
		}
	} else {
		log.Printf("authz: fetchOwnerIdentity error: %v", err)
	}

	// Resolve target PMS
	machineID, err := resolvePlexServerMachineID()
	if err != nil {
		return false, err
	}

	// 1) Check /shared_servers (matches by username; UUID not provided here)
	entries, err := fetchSharedServers(machineID)
	if err != nil {
		return false, err
	}
	unameLower := strings.ToLower(strings.TrimSpace(username))
	if unameLower != "" {
		for _, e := range entries {
			if strings.ToLower(e.Username) == unameLower {
				return true, nil
			}
		}
	}

	// 2) Fallback: Plex Home users (can match by UUID or username)
	home, err := fetchHomeUsers()
	if err != nil {
		log.Printf("authz: fetchHomeUsers error: %v", err)
		return false, nil
	}
	uuidTrim := strings.TrimSpace(userUUID)
	for _, u := range home {
		if uuidTrim != "" && u.UUID == uuidTrim {
			return true, nil
		}
		if unameLower != "" && strings.ToLower(u.Username) == unameLower {
			return true, nil
		}
	}

	return false, nil
}

// ---------------- Portal ----------------

func meHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"username": usernameFrom(r.Context()),
		"uuid":     uuidFrom(r.Context()),
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	uname := usernameFrom(r.Context())
	uid := uuidFrom(r.Context())

	authorized := false
	var err error
	if uname == "" && uid == "" {
		log.Printf("home: no username/uuid in session; treating as not authorized")
	} else {
		authorized, err = isUserAuthorizedOnServer(uid, uname)
		if err != nil {
			log.Printf("home authz check failed for %s (%s): %v", uname, uid, err)
		}
	}

	// If you want to ensure the DB reflects "authorized" even if the user first hit /home
	// via a fresh session (rare), you can opportunistically upsert here — ONLY when authorized.
	if authorized {
		// We don’t have the token here if the session is new and we skipped forward upsert,
		// but upsertUser tolerates NULL token/email. It will mark plex_access=true.
		_, _ = upsertUser(User{
			Username:   uname,
			PlexUUID:   nullStringFrom(uid),
			PlexAccess: true,
		})
	}

	if authorized {
		render(w, "portal_authorized.html", map[string]any{
			"Username": uname,
		})
		return
	}
	render(w, "portal_unauthorized.html", map[string]any{
		"Username": uname,
	})
}