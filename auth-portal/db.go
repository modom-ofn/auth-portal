// db.go
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/lib/pq"
)

// ---------- Schema ----------

func createSchema() error {
	// Create users table (provider-agnostic columns)
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  email         TEXT,
  media_uuid    TEXT UNIQUE,
  media_token   TEXT,
  media_access  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		return err
	}

	// One-time migration: rename old plex_* columns to media_* if they exist
	if _, err := db.Exec(`
DO $$
BEGIN
  BEGIN
    ALTER TABLE users RENAME COLUMN plex_uuid TO media_uuid;
  EXCEPTION WHEN undefined_column THEN NULL;
  END;
  BEGIN
    ALTER TABLE users RENAME COLUMN plex_token TO media_token;
  EXCEPTION WHEN undefined_column THEN NULL;
  END;
  BEGIN
    ALTER TABLE users RENAME COLUMN plex_access TO media_access;
  EXCEPTION WHEN undefined_column THEN NULL;
  END;
END $$;`); err != nil {
		return err
	}

	// Add any missing columns (no-ops if already present)
	if _, err := db.Exec(`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS media_access  BOOLEAN    NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
`); err != nil {
		return err
	}

	// Helpful indexes
	if _, err := db.Exec(`
CREATE INDEX IF NOT EXISTS idx_users_username    ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_media_uuid  ON users (media_uuid);
`); err != nil {
		return err
	}

	// MFA columns on users for quick checks
	if _, err := db.Exec(`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS mfa_enrolled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mfa_recovery_last_rotated TIMESTAMPTZ
`); err != nil {
		return err
	}

	// Per-user MFA secret metadata
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS user_mfa (
  user_id        BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc     TEXT,
  secret_algo    TEXT NOT NULL DEFAULT 'totp-sha1',
  digits         SMALLINT NOT NULL DEFAULT 6,
  period_seconds SMALLINT NOT NULL DEFAULT 30,
  drift_steps    SMALLINT NOT NULL DEFAULT 1,
  is_verified    BOOLEAN NOT NULL DEFAULT FALSE,
  issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at    TIMESTAMPTZ,
  last_used_at   TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_user_mfa_verified ON user_mfa (is_verified);
`); err != nil {
		return err
	}

	// Recovery codes (hashed) per user
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT   NOT NULL,
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON user_mfa_recovery_codes (user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_used ON user_mfa_recovery_codes (user_id, used_at);
`); err != nil {
		return err
	}

	// Identities table to support multi-provider identities
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS identities (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider      TEXT   NOT NULL,
  media_uuid    TEXT   NOT NULL,
  media_token   TEXT,
  media_access  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, media_uuid),
  UNIQUE (user_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_ident_provider_uuid ON identities (provider, media_uuid);
CREATE INDEX IF NOT EXISTS idx_ident_user_provider ON identities (user_id, provider);
`); err != nil {
		return err
	}

	// Backfill identities from legacy users columns when present
	if _, err := db.Exec(`
INSERT INTO identities (user_id, provider, media_uuid, media_token, media_access)
SELECT u.id,
       CASE
         WHEN media_uuid LIKE 'plex-%' THEN 'plex'
         WHEN media_uuid LIKE 'emby-%' THEN 'emby'
         WHEN media_uuid LIKE 'jellyfin-%' THEN 'jellyfin'
         ELSE 'media'
       END AS provider,
       media_uuid,
       media_token,
       media_access
  FROM users u
 WHERE media_uuid IS NOT NULL AND media_uuid <> ''
ON CONFLICT (provider, media_uuid) DO UPDATE
   SET media_token  = COALESCE(NULLIF(EXCLUDED.media_token, ''), identities.media_token),
       media_access = EXCLUDED.media_access,
       updated_at   = now();
`); err != nil {
		return err
	}

	// Pins table (unchanged)
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

// ---------- PIN storage ----------

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

// Backward-compatible struct: prefer Media* fields, but keep Plex* for callers
// that haven't been updated yet. upsertUser() will prefer Media* if provided.
type User struct {
	ID int

	Username string
	Email    sql.NullString

	// New, provider-agnostic fields
	MediaUUID   sql.NullString
	MediaToken  sql.NullString
	MediaAccess bool

	// Legacy (will be ignored if Media* are set)
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

// Choose values, preferring Media* (new) over Plex* (legacy)
func pickUUID(u User) string {
	if v := strings.TrimSpace(u.MediaUUID.String); u.MediaUUID.Valid && v != "" {
		return v
	}
	if v := strings.TrimSpace(u.PlexUUID.String); u.PlexUUID.Valid && v != "" {
		return v
	}
	return ""
}
func pickToken(u User) string {
	if v := strings.TrimSpace(u.MediaToken.String); u.MediaToken.Valid && v != "" {
		return v
	}
	if v := strings.TrimSpace(u.PlexToken.String); u.PlexToken.Valid && v != "" {
		return v
	}
	return ""
}
func pickAccess(u User) bool {
	// MediaAccess takes precedence; otherwise fall back to PlexAccess
	if u.MediaAccess {
		return true
	}
	return u.PlexAccess
}

// Upsert rules (media-agnostic):
// - If media_uuid present: upsert keyed on media_uuid
// - Else: upsert keyed on username
// - Never overwrite non-empty DB values with blanks
// - Always touch updated_at on change
func upsertUser(u User) (int, error) {
	if strings.TrimSpace(u.Username) == "" {
		return 0, errors.New("username required")
	}

	uuid := pickUUID(u)
	token := pickToken(u)
	access := pickAccess(u)

	// Prefer UUID path if present
	if uuid != "" {
		var id int
		err := db.QueryRow(`
	INSERT INTO users (media_uuid, username, email, media_token, media_access)
	VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), $5)
	ON CONFLICT (media_uuid) DO UPDATE
	SET username     = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
	    email        = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
	    media_token  = COALESCE(NULLIF(EXCLUDED.media_token, ''), users.media_token),
	    media_access = EXCLUDED.media_access,
	    updated_at   = now()
	RETURNING id
	`, uuid, strings.TrimSpace(u.Username), nn(u.Email), token, access).Scan(&id)
		if err == nil {
			return id, nil
		}
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "users_username_key" {
			err = db.QueryRow(`
	UPDATE users
	   SET email        = COALESCE(NULLIF($2, ''), users.email),
	       media_token  = COALESCE(NULLIF($3, ''), users.media_token),
	       media_access = $4,
	       media_uuid   = CASE WHEN users.media_uuid IS NULL OR users.media_uuid = '' THEN NULLIF($5, '') ELSE users.media_uuid END,
	       updated_at   = now()
	 WHERE username = $1
	 RETURNING id
	`, strings.TrimSpace(u.Username), nn(u.Email), token, access, uuid).Scan(&id)
			if err != nil {
				return 0, err
			}
			return id, nil
		}
		return 0, err
	}

	// Username path (no UUID yet)
	var id int
	err := db.QueryRow(`
INSERT INTO users (username, email, media_token, media_access)
VALUES (NULLIF($1, ''), NULLIF($2, ''), NULLIF($3, ''), $4)
ON CONFLICT (username) DO UPDATE
SET email        = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
    media_token  = COALESCE(NULLIF(EXCLUDED.media_token, ''), users.media_token),
    media_access = EXCLUDED.media_access,
    updated_at   = now()
RETURNING id
`, strings.TrimSpace(u.Username), nn(u.Email), token, access).Scan(&id)
	if err != nil {
		return 0, err
	}

	// If a UUID became known later, set it once (no overwrite if already set)
	if uuid != "" {
		if _, err := db.Exec(`
UPDATE users
   SET media_uuid = COALESCE(media_uuid, $2),
       updated_at = now()
 WHERE id = $1
`, id, uuid); err != nil {
			// Not fatal; just log
			log.Printf("upsertUser: uuid backfill failed for user id=%d: %v", id, err)
		}
	}

	return id, nil
}

// Set media_access by UUID (preferred, provider-agnostic)
func setUserMediaAccessByUUID(uuid string, access bool) error {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return fmt.Errorf("setUserMediaAccessByUUID: empty uuid")
	}
	_, err := db.Exec(`
UPDATE users
   SET media_access = $2,
       updated_at   = now()
 WHERE media_uuid = $1
`, uuid, access)
	return err
}

// Legacy shims (keep old callers working)
func setUserPlexAccessByUUID(uuid string, access bool) error {
	return setUserMediaAccessByUUID(uuid, access)
}
func setUserPlexAccess(uuid string, access bool) error { return setUserMediaAccessByUUID(uuid, access) }
