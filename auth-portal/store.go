// store.go
package main

import (
	"context"
	"time"
)

const dbTimeout = 5 * time.Second

// --- small internal helper to scan a single user row ---
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(rs rowScanner) (User, error) {
	var u User
	err := rs.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PlexUUID,
		&u.PlexToken,
		&u.PlexAccess,
	)
	return u, err
}

// ---------- Getters ----------

func getUserByID(id int) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return scanUser(db.QueryRowContext(ctx, `
SELECT id, username, email, plex_uuid, plex_token, plex_access
FROM users
WHERE id = $1`, id))
}

func getUserByUUID(uuid string) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return scanUser(db.QueryRowContext(ctx, `
SELECT id, username, email, plex_uuid, plex_token, plex_access
FROM users
WHERE plex_uuid = $1`, uuid))
}

func getUserByUsername(username string) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return scanUser(db.QueryRowContext(ctx, `
SELECT id, username, email, plex_uuid, plex_token, plex_access
FROM users
WHERE username = $1`, username))
}

// ---------- Mutators ----------

// Convenience setter when you only have the username.
// (Preferred path is setUserPlexAccessByUUID in db.go)
func setUserPlexAccessByUsername(username string, access bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	_, err := db.ExecContext(ctx, `
UPDATE users
SET plex_access = $1
WHERE username = $2`, access, username)
	return err
}

// NOTE: Do NOT define setUserPlexAccess here — it's already in db.go.