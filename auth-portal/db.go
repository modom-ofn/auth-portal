// db.go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

// db is initialized in main.go
// var db *sql.DB

// ---------- Schema ----------

func createSchema() error {
	// users table
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id           BIGSERIAL PRIMARY KEY,
  username     TEXT UNIQUE NOT NULL,
  email        TEXT,
  plex_uuid    TEXT UNIQUE,
  plex_token   TEXT,
  plex_access  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		return err
	}

	// upgrades (older DBs): add any missing columns/constraints safely
	if _, err := db.Exec(`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS plex_access BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
`); err != nil {
		return err
	}

	// helpful indexes
	if _, err := db.Exec(`
CREATE INDEX IF NOT EXISTS idx_users_username   ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_plex_uuid  ON users (plex_uuid);
`); err != nil {
		return err
	}

	// pins table for PIN→ID mapping during login
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS pins (
  code       TEXT PRIMARY KEY,
  pin_id     INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		return err
	}

	return nil
}

// ---------- PIN storage (used by startAuthWebHandler) ----------

func savePin(code string, pinID int) error {
	_, err := db.Exec(`
INSERT INTO pins (code, pin_id) VALUES ($1, $2)
ON CONFLICT (code) DO UPDATE
SET pin_id = EXCLUDED.pin_id,
    created_at = now()
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
	s = strings.TrimSpace(s)
	return sql.NullString{String: s, Valid: s != ""}
}

func strOrNil(ns sql.NullString) *string {
	if ns.Valid {
		s := strings.TrimSpace(ns.String)
		if s != "" {
			return &s
		}
	}
	return nil
}

// Upsert rules:
// - If plex_uuid present: upsert keyed on plex_uuid
// - Else: upsert keyed on username
// - Never overwrite non-empty DB values with blanks
// - Always touch updated_at on change
func upsertUser(u User) (int, error) {
	if strings.TrimSpace(u.Username) == "" {
		return 0, errors.New("username required")
	}

	// Gate elsewhere: do NOT call upsertUser for unauthorized users

	// Prefer UUID path if present
	if u.PlexUUID.Valid && strings.TrimSpace(u.PlexUUID.String) != "" {
		var id int
		err := db.QueryRow(`
INSERT INTO users (plex_uuid, username, email, plex_token, plex_access)
VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), $5)
ON CONFLICT (plex_uuid) DO UPDATE
SET username   = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
    email      = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
    plex_token = COALESCE(NULLIF(EXCLUDED.plex_token, ''), users.plex_token),
    plex_access= EXCLUDED.plex_access,
    updated_at = now()
RETURNING id
`, strings.TrimSpace(u.PlexUUID.String), strings.TrimSpace(u.Username), nn(u.Email), nn(u.PlexToken), u.PlexAccess).Scan(&id)
		if err != nil {
			return 0, err
		}
		return id, nil
	}

	// Username path (for users that don't yet have plex_uuid)
	var id int
	err := db.QueryRow(`
INSERT INTO users (username, email, plex_token, plex_access)
VALUES (NULLIF($1, ''), NULLIF($2, ''), NULLIF($3, ''), $4)
ON CONFLICT (username) DO UPDATE
SET email       = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
    plex_token  = COALESCE(NULLIF(EXCLUDED.plex_token, ''), users.plex_token),
    plex_access = EXCLUDED.plex_access,
    updated_at  = now()
RETURNING id
`, strings.TrimSpace(u.Username), nn(u.Email), nn(u.PlexToken), u.PlexAccess).Scan(&id)
	if err != nil {
		return 0, err
	}

	// If a uuid became known later, set it once (no overwrite if already set)
	if u.PlexUUID.Valid && strings.TrimSpace(u.PlexUUID.String) != "" {
		if _, err := db.Exec(`
UPDATE users
   SET plex_uuid = COALESCE(plex_uuid, $2),
       updated_at = now()
 WHERE id = $1
`, id, strings.TrimSpace(u.PlexUUID.String)); err != nil {
			// Not fatal; just log
			log.Printf("upsertUser: uuid backfill failed for user id=%d: %v", id, err)
		}
	}

	return id, nil
}

// Helper: return trimmed string or empty for NULLIF
func nn(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return strings.TrimSpace(ns.String)
}

func strOrEmpty(ns sql.NullString) string {
	if ns.Valid {
		return strings.TrimSpace(ns.String)
	}
	return ""
}

// Set plex_access by UUID (preferred)
func setUserPlexAccessByUUID(uuid string, access bool) error {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return fmt.Errorf("setUserPlexAccessByUUID: empty uuid")
	}
	_, err := db.Exec(`
UPDATE users
   SET plex_access = $2,
       updated_at  = now()
 WHERE plex_uuid = $1
`, uuid, access)
	return err
}

// Convenience: same name you were calling in homeHandler; treats the arg as UUID
func setUserPlexAccess(uuid string, access bool) error {
	return setUserPlexAccessByUUID(uuid, access)
}