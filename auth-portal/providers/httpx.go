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

func doWithRetry(req *http.Request) (*http.Response, error) {
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
			return nil, err
		}
		if resp.StatusCode >= 500 && resp.StatusCode < 600 && attempt == 0 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(120 * time.Millisecond)
			continue
		}
		break
	}
	return resp, err
}

func buildAuthRequest(baseURL, appName, appVersion, clientID string, body map[string]string) (*http.Request, error) {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/Users/AuthenticateByName"
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", mediaAuthHeader(appName, appVersion, clientID))
	req.Header.Set("X-Emby-Client", appName)
	req.Header.Set("X-Emby-Client-Version", appVersion)
	return req, nil
}

func buildUserDetailRequest(serverURL, token, userID string) (*http.Request, error) {
	u := strings.TrimSuffix(serverURL, "/") + "/Users/" + userID
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", fmt.Sprintf(`MediaBrowser Token="%s"`, token))
		req.Header.Set("X-MediaBrowser-Token", token)
	}
	return req, nil
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
		IsDisabled      bool `json:"IsDisabled"`
		IsAdministrator bool `json:"IsAdministrator"`
		IsAdmin         bool `json:"IsAdmin"`
	} `json:"Policy"`
}

// mediaAuthAttempt performs a POST to /Users/AuthenticateByName with the given JSON body fields.
func mediaAuthAttempt(prefix, baseURL, appName, appVersion, clientID string, body map[string]string) (mediaAuthResp, error) {
	req, err := buildAuthRequest(baseURL, appName, appVersion, clientID, body)
	if err != nil {
		return mediaAuthResp{}, err
	}
	if Debugf != nil {
		Debugf("%s/auth POST %s", prefix, req.URL.String())
	}
	resp, err := doWithRetry(req)
	if err != nil {
		return mediaAuthResp{}, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return mediaAuthResp{}, readErr
	}
	if resp.StatusCode != http.StatusOK {
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
	req, err := buildUserDetailRequest(serverURL, token, userID)
	if err != nil {
		return mediaUserDetail{}, err
	}
	if Debugf != nil {
		Debugf("%s/user GET %s (token=%v)", prefix, req.URL.String(), strings.TrimSpace(token) != "")
	}
	resp, err := doWithRetry(req)
	if err != nil {
		return mediaUserDetail{}, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return mediaUserDetail{}, readErr
	}
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
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(serverURL, "/")+"/users/Me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Emby-Token", token)

	resp, err := doWithRetry(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}
