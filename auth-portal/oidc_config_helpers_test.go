package main

import (
	"auth-portal/configstore"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictConfigRequest(t *testing.T) {
	for _, body := range []string{`{"unknown":1}`, `{} {}`, strings.Repeat(" ", 65536) + `{}`, `{`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PUT", "/", strings.NewReader(body))
		var target struct {
			Version int `json:"version"`
		}
		if decodeOIDCConfigRequest(w, r, &target) || w.Code != 400 {
			t.Fatal("invalid request accepted", w.Code)
		}
	}
	for _, reason := range []string{"", strings.Repeat("x", 201)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PUT", "/", nil)
		if saveOIDCSection(w, r, configstore.Section("fixture-policy"), struct{}{}, 0, reason) || w.Code != 400 {
			t.Fatal("invalid reason accepted")
		}
	}
}
