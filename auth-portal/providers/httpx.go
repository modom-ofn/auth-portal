package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// shared HTTP client with sane timeout
var httpx = &http.Client{Timeout: 10 * time.Second}

// mediaAuthHeader builds the MediaBrowser Authorization header
func mediaAuthHeader(appName, appVersion, clientID string) string {
	return fmt.Sprintf(`MediaBrowser Client="%s", Device="Web", DeviceId="%s", Version="%s"`, appName, clientID, appVersion)
}

// snippet returns a trimmed preview of a payload for logging/errors.
func snippet(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n]
	}
	return s
}

// mediaAuthResp matches Emby/Jellyfin auth response shape.
type mediaAuthResp struct {
	AccessToken string `json:"AccessToken"`
	User        struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	} `json:"User"`
}

// mediaUserDetail matches Emby/Jellyfin /Users/{id} shape.
type mediaUserDetail struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Policy struct {
		IsDisabled bool `json:"IsDisabled"`
	} `json:"Policy"`
}

// mediaAuthAttempt performs a POST to /Users/AuthenticateByName with the given JSON body fields.
func mediaAuthAttempt(prefix, baseURL, appName, appVersion, clientID string, body map[string]string) (mediaAuthResp, error) {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/Users/AuthenticateByName"
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", mediaAuthHeader(appName, appVersion, clientID))
	req.Header.Set("X-Emby-Client", appName)
	req.Header.Set("X-Emby-Client-Version", appVersion)
	if Debugf != nil {
		Debugf("%s/auth POST %s", prefix, loginURL)
	}
	// one retry on net error or 5xx
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = httpx.Do(req)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(120 * time.Millisecond)
				continue
			}
			// retry once for any network error
			if attempt == 0 {
				time.Sleep(120 * time.Millisecond)
				continue
			}
			return mediaAuthResp{}, err
		}
		if resp.StatusCode >= 500 && resp.StatusCode < 600 && attempt == 0 {
			// read+discard to allow connection reuse before retry
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(120 * time.Millisecond)
			continue
		}
		break
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if Warnf != nil {
			Warnf("%s/auth HTTP %d body=%q", prefix, resp.StatusCode, snippet(raw, 200))
		}
		return mediaAuthResp{}, fmt.Errorf("%s auth %d: %s", prefix, resp.StatusCode, snippet(raw, 200))
	}
	var out mediaAuthResp
	if err := json.Unmarshal(raw, &out); err != nil {
		if Warnf != nil {
			Warnf("%s/auth decode failed: %v body=%q", prefix, err, snippet(raw, 200))
		}
		return mediaAuthResp{}, fmt.Errorf("%s auth decode failed: %w", prefix, err)
	}
	return out, nil
}

// mediaGetUserDetail performs a GET to /Users/{id} using either an API key or access token.
func mediaGetUserDetail(prefix, serverURL, token, userID string) (mediaUserDetail, error) {
	u := strings.TrimSuffix(serverURL, "/") + "/Users/" + userID
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", fmt.Sprintf(`MediaBrowser Token="%s"`, token))
		req.Header.Set("X-MediaBrowser-Token", token)
	}
	if Debugf != nil {
		Debugf("%s/user GET %s (token=%v)", prefix, u, token != "")
	}
	// one retry on net error or 5xx
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = httpx.Do(req)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(120 * time.Millisecond)
				continue
			}
			if attempt == 0 {
				time.Sleep(120 * time.Millisecond)
				continue
			}
			return mediaUserDetail{}, err
		}
		if resp.StatusCode >= 500 && resp.StatusCode < 600 && attempt == 0 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(120 * time.Millisecond)
			continue
		}
		break
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if Warnf != nil {
			Warnf("%s/user HTTP %d body=%q", prefix, resp.StatusCode, snippet(raw, 200))
		}
		return mediaUserDetail{}, fmt.Errorf("%s user %d: %s", prefix, resp.StatusCode, snippet(raw, 200))
	}
	var out mediaUserDetail
	if err := json.Unmarshal(raw, &out); err != nil {
		if Warnf != nil {
			Warnf("%s/user decode failed: %v body=%q", prefix, err, snippet(raw, 200))
		}
		return mediaUserDetail{}, fmt.Errorf("%s user decode failed: %w", prefix, err)
	}
	return out, nil
}

// mediaTokenStillValid checks whether X-Emby-Token is currently accepted by the server.
func mediaTokenStillValid(prefix, serverURL, token string) (bool, error) {
	req, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(serverURL, "/")+"/users/Me", nil)
	req.Header.Set("X-Emby-Token", token)

	var resp *http.Response
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = httpx.Do(req)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(120 * time.Millisecond)
				continue
			}
			if attempt == 0 {
				time.Sleep(120 * time.Millisecond)
				continue
			}
			return false, err
		}
		if resp.StatusCode >= 500 && resp.StatusCode < 600 && attempt == 0 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(120 * time.Millisecond)
			continue
		}
		break
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}
