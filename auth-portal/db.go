// db.go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
)

// db is initialized in main.go
// var db *sql.DB

// ---------- Schema ----------

func createSchema() error {
	// users table
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id           SERIAL PRIMARY KEY,
  username     TEXT UNIQUE NOT NULL,
  email        TEXT,
  plex_uuid    TEXT UNIQUE,
  plex_token   TEXT,
  plex_access  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ DEFAULT now()
)`); err != nil {
		return err
	}

	// upgrades (older DBs)
	if _, err := db.Exec(`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS plex_access BOOLEAN NOT NULL DEFAULT FALSE
`); err != nil {
		return err
	}

	// helpful indexes
	if _, err := db.Exec(`
CREATE INDEX IF NOT EXISTS idx_users_username  ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_plex_uuid ON users (plex_uuid);
`); err != nil {
		return err
	}

	// pins table for PIN→ID mapping during login
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS pins (
  code       TEXT PRIMARY KEY,
  pin_id     INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
)`); err != nil {
		return err
	}

	return nil
}

// ---------- PIN storage (used by startAuthWebHandler) ----------

func savePin(code string, pinID int) error {
	_, err := db.Exec(`
INSERT INTO pins (code, pin_id) VALUES ($1, $2)
ON CONFLICT (code) DO UPDATE SET pin_id = EXCLUDED.pin_id, created_at = now()
`, code, pinID)
	return err
}

func getPinIDByCode(code string) (int, error) {
	var id int
	err := db.QueryRow(`SELECT pin_id FROM pins WHERE code = $1`, code).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ---------- Users ----------

type User struct {
	ID         int
	Username   string
	Email      sql.NullString
	PlexUUID   sql.NullString
	PlexToken  sql.NullString
	PlexAccess bool
}

func nullStringFrom(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// Upsert on (username) and keep plex_uuid unique if provided.
// If plex_uuid already exists on another row, this will error—by design.
func upsertUser(u User) (int, error) {
	if u.Username == "" {
		return 0, errors.New("username required")
	}

	// If a UUID is provided, try to tie by uuid first (so we don't create dup rows for same person)
	if u.PlexUUID.Valid && u.PlexUUID.String != "" {
		// Try update by uuid
		res, err := db.Exec(`
UPDATE users
   SET username = COALESCE($2, username),
       email    = $3,
       plex_token = $4,
       updated_at = now()
 WHERE plex_uuid = $1
`, u.PlexUUID.String, u.Username, u.Email, u.PlexToken)
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				// fetch id
				var id int
				if err := db.QueryRow(`SELECT id FROM users WHERE plex_uuid=$1`, u.PlexUUID.String).Scan(&id); err == nil {
					return id, nil
				}
			}
		}
		// If no row updated, fall through to username upsert (and keep uuid)
	}

	// Upsert on username; if a uuid was provided and this row has no uuid yet, set it.
	var id int
	err := db.QueryRow(`
INSERT INTO users (username, email, plex_uuid, plex_token, plex_access)
VALUES ($1, $2, NULLIF($3,''), $4, COALESCE($5,false))
ON CONFLICT (username) DO UPDATE
   SET email      = EXCLUDED.email,
       plex_token = EXCLUDED.plex_token
RETURNING id
`, u.Username, u.Email, strOrEmpty(u.PlexUUID), u.PlexToken, u.PlexAccess).Scan(&id)
	if err != nil {
		return 0, err
	}

	// If we just created/updated and a uuid is provided, backfill uuid if empty
	if u.PlexUUID.Valid && u.PlexUUID.String != "" {
		if _, err := db.Exec(`
UPDATE users
   SET plex_uuid = COALESCE(plex_uuid, $2)
 WHERE id = $1
`, id, u.PlexUUID.String); err != nil {
			// Not fatal, just log
			log.Printf("upsertUser: uuid backfill failed for %s: %v", u.Username, err)
		}
	}

	return id, nil
}

func strOrEmpty(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// Set plex_access by UUID (preferred)
func setUserPlexAccessByUUID(uuid string, access bool) error {
	if uuid == "" {
		return fmt.Errorf("setUserPlexAccessByUUID: empty uuid")
	}
	_, err := db.Exec(`
UPDATE users SET plex_access = $2 WHERE plex_uuid = $1
`, uuid, access)
	return err
}

// Convenience: same name you were calling in homeHandler; treats the arg as UUID
func setUserPlexAccess(uuid string, access bool) error {
	return setUserPlexAccessByUUID(uuid, access)
}