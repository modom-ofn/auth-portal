// context_helpers.go
package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

// Per-request context keys
type userKey struct{}
type uuidKey struct{}

// Stash values in context
func withUsername(ctx context.Context, u string) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}
func withUUID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, uuidKey{}, id)
}

// Retrieve values from context
func usernameFrom(ctx context.Context) string {
	if v := ctx.Value(userKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
func uuidFrom(ctx context.Context) string {
	if v := ctx.Value(uuidKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// render loads a template from ./templates and executes it with data.
// (Simple helper; if you later add shared layouts/partials, you may
// switch to ParseFiles with multiple paths or a pre-parsed template set.)
func render(w http.ResponseWriter, tmpl string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tplPath := filepath.Join("templates", tmpl)
	t, err := template.ParseFiles(tplPath)
	if err != nil {
		log.Printf("render: template parse failed (%s): %v", tplPath, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	if err := t.Execute(w, data); err != nil {
		log.Printf("render: execute failed (%s): %v", tplPath, err)
		http.Error(w, "Template execution error", http.StatusInternalServerError)
	}
}
