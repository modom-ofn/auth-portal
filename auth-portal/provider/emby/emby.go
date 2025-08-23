package main

import (
	"fmt"
	"net/http"
)

type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }

func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Emby login not implemented yet", http.StatusNotImplemented)
}

func (embyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Emby forward not implemented yet", http.StatusNotImplemented)
}

func (embyProvider) IsAuthorized(userUUID, username string) (bool, error) {
	return false, fmt.Errorf("Emby authorization not implemented yet")
}

// owner capture helpers

type embyOwner struct {
	ID       string
	Name     string
	Connect  string // ConnectUserName if present
}

var (
	embyOwnerCache     embyOwner
	embyOwnerCacheTime time.Time
)

func (p embyProvider) fetchOwner() (embyOwner, error) {
	// Cache ~10m
	if time.Since(embyOwnerCacheTime) < 10*time.Minute && embyOwnerCache.ID != "" {
		return embyOwnerCache, nil
	}
	if p.apiKey == "" || p.serverURL == "" {
		return embyOwner{}, fmt.Errorf("EMBY_API_KEY and EMBY_SERVER_URL are required")
	}

	req, _ := http.NewRequest("GET", strings.TrimRight(p.serverURL, "/")+"/Users", nil)
	req.Header.Set("X-Emby-Token", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return embyOwner{}, fmt.Errorf("emby /Users request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return embyOwner{}, fmt.Errorf("emby /Users returned %d: %s", resp.StatusCode, string(b))
	}

	var users []struct {
		Id              string `json:"Id"`
		Name            string `json:"Name"`
		ConnectUserName string `json:"ConnectUserName"`
		Policy struct {
			IsAdministrator bool `json:"IsAdministrator"`
		} `json:"Policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return embyOwner{}, fmt.Errorf("emby /Users decode: %w", err)
	}

	wantID := os.Getenv("EMBY_OWNER_ID")
	wantUser := strings.TrimSpace(os.Getenv("EMBY_OWNER_USERNAME"))

	var admins []embyOwner
	for _, u := range users {
		if u.Policy.IsAdministrator {
			admins = append(admins, embyOwner{ID: u.Id, Name: u.Name, Connect: u.ConnectUserName})
		}
	}

	// Choose by ID → username → fallback first admin
	pick := embyOwner{}
	if wantID != "" {
		for _, a := range admins {
			if a.ID == wantID {
				pick = a
				break
			}
		}
	} else if wantUser != "" {
		wl := strings.ToLower(wantUser)
		for _, a := range admins {
			if strings.EqualFold(a.Name, wantUser) || strings.EqualFold(a.Connect, wantUser) || strings.ToLower(a.Connect) == wl {
				pick = a
				break
			}
		}
	}
	if pick.ID == "" && len(admins) > 0 {
		pick = admins[0]
	}
	if pick.ID == "" {
		return embyOwner{}, fmt.Errorf("no Emby administrator user found")
	}

	embyOwnerCache = pick
	embyOwnerCacheTime = time.Now()
	return pick, nil
}

// isUserAuthorizedOnEmby checks presence of a non-disabled Emby user and short-circuits for owner/admin.
func (p embyProvider) isUserAuthorizedOnEmby(userID, username string) (bool, error) {
	owner, err := p.fetchOwner()
	if err == nil {
		if userID != "" && userID == owner.ID {
			return true, nil
		}
		if username != "" && (strings.EqualFold(username, owner.Name) || strings.EqualFold(username, owner.Connect)) {
			return true, nil
		}
	}

	req, _ := http.NewRequest("GET", strings.TrimRight(p.serverURL, "/")+"/Users", nil)
	req.Header.Set("X-Emby-Token", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("emby /Users request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("emby /Users returned %d: %s", resp.StatusCode, string(b))
	}

	var users []struct {
		Id              string `json:"Id"`
		Name            string `json:"Name"`
		ConnectUserName string `json:"ConnectUserName"`
		Policy struct {
			IsAdministrator bool `json:"IsAdministrator"`
		} `json:"Policy"`
		// (Some servers include IsDisabled in User; if not present, treat presence as enabled.)
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return false, fmt.Errorf("emby /Users decode: %w", err)
	}

	un := strings.ToLower(strings.TrimSpace(username))
	for _, u := range users {
		if userID != "" && u.Id == userID {
			return true, nil
		}
		if un != "" && (strings.EqualFold(u.Name, username) || strings.EqualFold(u.ConnectUserName, username)) {
			return true, nil
		}
	}
	return false, nil
}
