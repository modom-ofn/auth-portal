package providers

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "sync/atomic"
    "testing"
)

func TestMediaAuthAttempt_Success(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/Users/AuthenticateByName" {
            t.Fatalf("unexpected path: %s", r.URL.Path)
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{
            "AccessToken": "tok123",
            "User": map[string]any{"Id": "u1", "Name": "alice"},
        })
    }))
    defer ts.Close()

    out, err := mediaAuthAttempt("jellyfin", ts.URL, "AuthPortal", "2.0.1", "cid", map[string]string{"Username": "a", "Password": "b"})
    if err != nil { t.Fatalf("unexpected err: %v", err) }
    if out.AccessToken != "tok123" || out.User.ID != "u1" || out.User.Name != "alice" {
        t.Fatalf("unexpected response: %+v", out)
    }
}

func TestMediaAuthAttempt_RetryOn5xx(t *testing.T) {
    var calls int32
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c := atomic.AddInt32(&calls, 1)
        if c == 1 {
            http.Error(w, "temp", http.StatusServiceUnavailable)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{
            "AccessToken": "tok456",
            "User": map[string]any{"Id": "u2", "Name": "bob"},
        })
    }))
    defer ts.Close()

    out, err := mediaAuthAttempt("emby", ts.URL, "AuthPortal", "2.0.1", "cid", map[string]string{"Username": "a", "Password": "b"})
    if err != nil { t.Fatalf("unexpected err: %v", err) }
    if out.AccessToken != "tok456" || out.User.ID != "u2" { t.Fatalf("bad: %+v", out) }
    if atomic.LoadInt32(&calls) != 2 { t.Fatalf("expected 2 calls, got %d", calls) }
}

func TestMediaAuthAttempt_BadJSON(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte("not-json"))
    }))
    defer ts.Close()

    _, err := mediaAuthAttempt("emby", ts.URL, "AuthPortal", "2.0.1", "cid", map[string]string{"Username": "a", "Password": "b"})
    if err == nil { t.Fatal("expected error") }
}

func TestMediaGetUserDetail_RetryOn5xx(t *testing.T) {
    var calls int32
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c := atomic.AddInt32(&calls, 1)
        if c == 1 {
            http.Error(w, "temp", http.StatusBadGateway)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{
            "Id": "u9",
            "Name": "neo",
            "Policy": map[string]any{"IsDisabled": false},
        })
    }))
    defer ts.Close()

    out, err := mediaGetUserDetail("emby", ts.URL, "k", "u9")
    if err != nil { t.Fatalf("unexpected err: %v", err) }
    if out.ID != "u9" || out.Policy.IsDisabled { t.Fatalf("bad: %+v", out) }
    if atomic.LoadInt32(&calls) != 2 { t.Fatalf("expected 2 calls, got %d", calls) }
}

func TestMediaTokenStillValid_RetryOn5xx(t *testing.T) {
    var calls int32
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c := atomic.AddInt32(&calls, 1)
        if c == 1 {
            http.Error(w, "temp", http.StatusBadGateway)
            return
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer ts.Close()

    ok, err := mediaTokenStillValid("emby", ts.URL, "tok")
    if err != nil { t.Fatalf("unexpected err: %v", err) }
    if !ok { t.Fatal("expected ok=true") }
    if atomic.LoadInt32(&calls) != 2 { t.Fatalf("expected 2 calls, got %d", calls) }
}
