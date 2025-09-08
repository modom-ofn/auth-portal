package main

import "net/http"

// MediaProvider defines the methods required for a media server provider.
type MediaProvider interface {
	// Name returns a short identifier for the provider (e.g. "plex").
	Name() string
	// StartWeb initiates the provider's web-based authentication flow.
	StartWeb(w http.ResponseWriter, r *http.Request)
	// Forward processes authentication submissions or token exchanges.
	Forward(w http.ResponseWriter, r *http.Request)
	// IsAuthorized checks if the given user is authorized in the provider's system.
	IsAuthorized(uuid, username string) (bool, error)
}
