package main

import (
	"net/http"
)

// MediaProvider defines the minimal surface the app needs from an auth provider.
type MediaProvider interface {
	Name() string
	// StartWeb kicks off the auth flow (popup for Plex, credential form for Emby, etc.)
	StartWeb(w http.ResponseWriter, r *http.Request)
	// Forward completes the flow (Plex popup callback). For providers that don't use it,
	// they can return 501.
	Forward(w http.ResponseWriter, r *http.Request)
}

//
// -------- Plex provider (wraps your existing handlers) --------
//

type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

func (plexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	// Uses your existing Plex "start web" handler
	startAuthWebHandler(w, r)
}

func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	// Uses your existing Plex "forward" handler
	forwardHandler(w, r)
}

//
// -------- Emby provider (stub for now) --------
//   Implement your credential-based flow here later (StartWeb/Forward).
//

type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }

func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	// Placeholder: implement Emby credential login here later
	http.Error(w, "Emby auth: not implemented yet", http.StatusNotImplemented)
}

func (embyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	// Emby won’t use the Plex-style /auth/forward popup callback
	http.Error(w, "Emby forward: not applicable", http.StatusNotImplemented)
}