// db.go
package main

import (
	"database/sql"
	"errors"
	"log"
	"strings"

	"github.com/lib/pq"
)

// ---------- Schema ----------

func createSchema() error {
	statements := []string{
		`
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  email         TEXT,
  media_uuid    TEXT UNIQUE,
  media_token   TEXT,
  media_access  BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
)`,
		`
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
END $$;`,
		`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS media_access  BOOLEAN    NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
`,
		`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin         BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS admin_granted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admin_granted_by TEXT,
  ADD COLUMN IF NOT EXISTS session_version  BIGINT      NOT NULL DEFAULT 0
`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users (is_admin);`,
		`
CREATE INDEX IF NOT EXISTS idx_users_username    ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_media_uuid  ON users (media_uuid);
`,
		`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS mfa_enrolled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mfa_recovery_last_rotated TIMESTAMPTZ
`,
		`
CREATE TABLE IF NOT EXISTS roles (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles (name);
`,
		`
CREATE TABLE IF NOT EXISTS permissions (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions (name);
`,
		`
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions (permission_id);
`,
		`
CREATE TABLE IF NOT EXISTS user_roles (
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id     BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  assigned_by TEXT,
  PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role_id);
`,
		`
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ
`,
		`CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users (last_seen_at DESC);`,
		`
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
`,
		`
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
`,
		`
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
`,
		`
INSERT INTO identities (user_id, provider, media_uuid, media_token, media_access)
SELECT u.id,
       CASE
         WHEN media_uuid LIKE 'plex-%' THEN 'plex'
         WHEN media_uuid LIKE 'emby-%' THEN 'emby'
         WHEN media_uuid LIKE 'jellyfin-%' THEN 'jellyfin'
         ELSE NULL
       END AS provider,
       media_uuid,
       media_token,
       media_access
  FROM users u
 WHERE media_uuid IS NOT NULL
   AND media_uuid <> ''
   AND (
     media_uuid LIKE 'plex-%'
     OR media_uuid LIKE 'emby-%'
     OR media_uuid LIKE 'jellyfin-%'
   )
ON CONFLICT (provider, media_uuid) DO UPDATE
   SET media_token  = COALESCE(NULLIF(EXCLUDED.media_token, ''), identities.media_token),
       media_access = EXCLUDED.media_access,
       updated_at   = now();
`,
		`
CREATE TABLE IF NOT EXISTS pins (
  code       TEXT PRIMARY KEY,
  pin_id     INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`,
		`
CREATE TABLE IF NOT EXISTS app_config (
  namespace   TEXT   NOT NULL,
  key         TEXT   NOT NULL,
  value       JSONB  NOT NULL,
  version     BIGINT NOT NULL DEFAULT 1,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by  TEXT,
  PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_app_config_namespace ON app_config (namespace);
`,
		`
CREATE TABLE IF NOT EXISTS app_config_history (
  id            BIGSERIAL PRIMARY KEY,
  namespace     TEXT   NOT NULL,
  key           TEXT   NOT NULL,
  value         JSONB  NOT NULL,
  version       BIGINT NOT NULL,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by    TEXT,
  change_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_app_config_history_lookup ON app_config_history (namespace, key, version);
`,
		`
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id      TEXT PRIMARY KEY,
  client_secret  TEXT,
  name           TEXT NOT NULL,
  redirect_uris  TEXT[] NOT NULL DEFAULT '{}',
  scopes         TEXT[] NOT NULL DEFAULT '{}',
  grant_types    TEXT[] NOT NULL DEFAULT '{}',
  response_types TEXT[] NOT NULL DEFAULT '{}',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_name ON oauth_clients (name);
`,
		`
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  code            TEXT PRIMARY KEY,
  client_id       TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes          TEXT[] NOT NULL DEFAULT '{}',
  redirect_uri    TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  consumed_at     TIMESTAMPTZ,
  code_challenge  TEXT,
  code_method     TEXT,
  nonce           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_client ON oauth_auth_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_user ON oauth_auth_codes (user_id);
`,
		`
ALTER TABLE oauth_auth_codes
  ADD COLUMN IF NOT EXISTS nonce TEXT;
`,
		`
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
  token_id        TEXT PRIMARY KEY,
  client_id       TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes          TEXT[] NOT NULL DEFAULT '{}',
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client ON oauth_access_tokens (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user ON oauth_access_tokens (user_id);
`,
		`
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_id        TEXT PRIMARY KEY,
  access_token_id TEXT NOT NULL REFERENCES oauth_access_tokens(token_id) ON DELETE CASCADE,
  client_id       TEXT NOT NULL,
  user_id         BIGINT NOT NULL,
  scopes          TEXT[] NOT NULL DEFAULT '{}',
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (access_token_id)
);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client ON oauth_refresh_tokens (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user ON oauth_refresh_tokens (user_id);
`,
		`
CREATE TABLE IF NOT EXISTS oauth_consents (
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id  TEXT   NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scopes     TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_oauth_consents_client ON oauth_consents (client_id);
`,
	}

	return execStatements(statements)
}

func execStatements(statements []string) error {
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
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

	// Administrative control
	IsAdmin        bool
	AdminGrantedAt sql.NullTime
	AdminGrantedBy sql.NullString
	SessionVersion int64

	// Legacy (will be ignored if Media* are set)
	PlexUUID   sql.NullString
	PlexToken  sql.NullString
	PlexAccess bool
}

func nullStringFrom(s string) sql.NullString {
	s = strings.TrimSpace(s)
	return sql.NullString{String: s, Valid: s != ""}
}

// Helper: return trimmed string or empty for NULLIF
func nn(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return strings.TrimSpace(ns.String)
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

//lint:ignore U1000 kept for future provider use (UUID-based access toggles)
