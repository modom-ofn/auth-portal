package main

import (
	"database/sql"
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

type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

// You can still override via env later if you want.
var plexClientID = "auth-portal-go"

// ---------------------- StartWeb (popup) ----------------------

func (plexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
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

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
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

	_ = savePin(pin.Code, pin.ID)

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

// ---------------------- Forward (popup return) ----------------------

func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
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

	var tokenResp struct{ AuthToken string `json:"authToken"` }
	ok := false
	for i := 0; i < 6; i++ { // ~9s
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
		profile, perr := plexFetchUserProfile(tokenResp.AuthToken)
		if perr == nil {
			authorized := false
			if okAuth, err := plexIsAuthorizedOnServer(profile.UUID, profile.Username); err == nil {
				authorized = okAuth
			} else {
				log.Printf("authz check failed after login for %s (%s): %v", profile.Username, profile.UUID, err)
			}

			if authorized {
				var encTok sql.NullString
				if enc, err := sealToken(profile.Token); err != nil {
					log.Printf("token encrypt error: %v", err)
				} else {
					encTok = nullStringFrom(enc)
				}

				if _, err := upsertUser(User{
					Username:   profile.Username,
					Email:      nullStringFrom(profile.Email),
					PlexUUID:   nullStringFrom(profile.UUID),
					PlexToken:  encTok,
					PlexAccess: true,
				}); err != nil {
					log.Printf("upsertUser error (authorized): %v", err)
				}
			} else {
				log.Printf("skipping DB persist for unauthorized user %q (%s)", profile.Username, profile.UUID)
			}

			if err := setSessionCookie(w, profile.UUID, profile.Username); err != nil {
				log.Printf("setSessionCookie error: %v", err)
			}
		} else {
			ok = false
		}
	}

	// tiny page to notify opener and close
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

// ---------------------- Profile + authz ----------------------

func plexFetchUserProfile(authToken string) (Profile, error) {
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
		return Profile{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Profile{}, fmt.Errorf("Plex API returned %d: %s", resp.StatusCode, string(body))
	}
	if len(body) > 0 && body[0] == '<' {
		return Profile{}, fmt.Errorf("expected JSON but got XML/HTML")
	}

	var ar struct {
		User struct {
			ID       int    `json:"id"`
			UUID     string `json:"uuid"`
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		return Profile{}, fmt.Errorf("JSON decode failed: %w", err)
	}

	return Profile{
		UUID:     strings.TrimSpace(ar.User.UUID),
		Username: strings.TrimSpace(ar.User.Username),
		Email:    strings.TrimSpace(ar.User.Email),
		Token:    authToken,
	}, nil
}

// ---------- Authorization helpers ----------

type plexDeviceList struct {
	XMLName xml.Name   `xml:"MediaContainer"`
	Devices []plexDevice `xml:"Device"`
}
type plexDevice struct {
	Name             string `xml:"name,attr"`
	Provides         string `xml:"provides,attr"`
	ClientIdentifier string `xml:"clientIdentifier,attr"`
	Product          string `xml:"product,attr"`
}

var cachedMachineID string
var cachedMachineIDTime time.Time

func plexResolveServerMachineID() (string, error) {
	if plexOwnerToken == "" {
		return "", fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}
	if plexServerMachineID != "" {
		return plexServerMachineID, nil
	}
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

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("resources returned %d: %s", resp.StatusCode, string(b))
	}

	var dl plexDeviceList
	if err := xml.NewDecoder(resp.Body).Decode(&dl); err != nil {
		return "", fmt.Errorf("resources xml decode: %w", err)
	}

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

type sharedServersDoc struct {
	XMLName       xml.Name            `xml:"MediaContainer"`
	SharedServers []sharedServerEntry `xml:"SharedServer"`
}
type sharedServerEntry struct {
	ID       int    `xml:"id,attr"`
	Username string `xml:"username,attr"`
	Email    string `xml:"email,attr"`
	UserID   int    `xml:"userID,attr"`
	Owned    int    `xml:"owned,attr"`
}

var (
	sharedCacheMu sync.Mutex
	sharedCache   = struct {
		machineID string
		fetched   time.Time
		entries   []sharedServerEntry
	}{}
)

func plexFetchSharedServers(machineID string) ([]sharedServerEntry, error) {
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

type homeUsers struct{ Users []homeUser `xml:"User"` }
type homeUser struct {
	ID       int    `xml:"id,attr"`
	UUID     string `xml:"uuid,attr"`
	Username string `xml:"username,attr"`
}

func plexFetchHomeUsers() ([]homeUser, error) {
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

func plexIsAuthorizedOnServer(userUUID, username string) (bool, error) {
	if plexOwnerToken == "" {
		return false, fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}

	// owner short-circuit
	if owner, err := plexFetchOwnerIdentity(); err == nil {
		if (userUUID != "" && strings.EqualFold(userUUID, owner.UUID)) ||
			(username != "" && strings.EqualFold(username, owner.Username)) {
			return true, nil
		}
	} else {
		log.Printf("authz: owner identity error: %v", err)
	}

	machineID, err := plexResolveServerMachineID()
	if err != nil {
		return false, err
	}

	entries, err := plexFetchSharedServers(machineID)
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

	home, err := plexFetchHomeUsers()
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

type ownerAccount struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
}

var (
	ownerCache     ownerAccount
	ownerCacheTime time.Time
)

func plexFetchOwnerIdentity() (ownerAccount, error) {
	if plexOwnerToken == "" {
		return ownerAccount{}, fmt.Errorf("PLEX_OWNER_TOKEN not set")
	}
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

	var acc struct {
		User struct {
			UUID     string `json:"uuid"`
			Username string `json:"username"`
		} `json:"user"`
	}
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