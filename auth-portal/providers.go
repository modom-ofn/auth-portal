package main

import (
	"net/http"
)

// MediaProvider is the minimal surface the app needs from a media auth provider.
type MediaProvider interface {
	Name() string
	// StartWeb kicks off the auth flow (popup for Plex, credential form for Emby, etc.)
	StartWeb(w http.ResponseWriter, r *http.Request)
	// Forward completes the flow (e.g., Plex popup callback).
	Forward(w http.ResponseWriter, r *http.Request)
	// IsAuthorized returns whether the given user/uuid is authorized.
	// (Signature matches handlers.go use: (uuid, username) -> (bool, error))
	IsAuthorized(uuid, username string) (bool, error)
}

// -------- Plex provider --------

type plexProvider struct{}

func (plexProvider) Name() string { return "plex" }

func (plexProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	// TODO: implement real Plex start flow
	http.Error(w, "Plex StartWeb not implemented yet", http.StatusNotImplemented)
}

func (plexProvider) Forward(w http.ResponseWriter, r *http.Request) {
	// TODO: implement real Plex forward/callback flow
	http.Error(w, "Plex Forward not implemented yet", http.StatusNotImplemented)
}

func (plexProvider) IsAuthorized(uuid, username string) (bool, error) {
	// TODO: replace with real Plex access check
	// For now, treat any valid session user as authorized.
	return true, nil
}

// -------- Emby provider --------

type embyProvider struct{}

func (embyProvider) Name() string { return "emby" }

func (embyProvider) StartWeb(w http.ResponseWriter, r *http.Request) {
	// TODO: implement Emby login/handshake
	http.Error(w, "Emby StartWeb not implemented yet", http.StatusNotImplemented)
}

func (embyProvider) Forward(w http.ResponseWriter, r *http.Request) {
	// TODO: implement Emby callback/finish
	http.Error(w, "Emby Forward not implemented yet", http.StatusNotImplemented)
}

func (embyProvider) IsAuthorized(uuid, username string) (bool, error) {
	// TODO: replace with real Emby access check
	return true, nil
}