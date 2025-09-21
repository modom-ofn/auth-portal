package main

import (
    "context"
    "database/sql"
    "strings"
    "time"
)

const dbTimeout = 5 * time.Second

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(rs rowScanner) (User, error) {
	var u User
	err := rs.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.MediaUUID,
		&u.MediaToken,
		&u.MediaAccess,
	)
	return u, err
}

// ---------- Getters ----------

func getUserByID(id int) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return scanUser(db.QueryRowContext(ctx, `
SELECT id, username, email, media_uuid, media_token, media_access
FROM users
WHERE id = $1`, id))
}

func getUserByUUID(uuid string) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	var row User
	err := db.QueryRowContext(ctx, `
		SELECT id, username, email, media_uuid, media_token, media_access
		FROM users
		WHERE media_uuid = $1
	`, uuid).Scan(
		&row.ID,
		&row.Username,
		&row.Email,
		&row.MediaUUID,
		&row.MediaToken,
		&row.MediaAccess,
	)
	if err != nil {
		return User{}, err
	}

	// Decrypt token if present
	if row.MediaToken.Valid && row.MediaToken.String != "" {
		if pt, decErr := unsealToken(row.MediaToken.String); decErr == nil {
			row.MediaToken = sql.NullString{String: pt, Valid: true}
		} else {
			row.MediaToken = sql.NullString{}
		}
	}

	return row, nil
}

func getUserByUsername(username string) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	var row User
	err := db.QueryRowContext(ctx, `
		SELECT id, username, email, media_uuid, media_token, media_access
		FROM users
		WHERE username = $1
	`, username).Scan(
		&row.ID,
		&row.Username,
		&row.Email,
		&row.MediaUUID,
		&row.MediaToken,
		&row.MediaAccess,
	)
	if err != nil {
		return User{}, err
	}

	if row.MediaToken.Valid && row.MediaToken.String != "" {
		if pt, decErr := unsealToken(row.MediaToken.String); decErr == nil {
			row.MediaToken = sql.NullString{String: pt, Valid: true}
		} else {
			row.MediaToken = sql.NullString{}
		}
	}

	return row, nil
}

// ---------- Mutators ----------

func setUserMediaAccessByUsername(username string, access bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	_, err := db.ExecContext(ctx, `
UPDATE users
SET media_access = $1
WHERE username = $2`, access, username)
	return err
}

// Back-compat shim (older code still calling Plex-named helper)
func setUserPlexAccessByUsername(username string, access bool) error {
    return setUserMediaAccessByUsername(username, access)
}

// getUserByUUIDPreferred first tries the identities table, then falls back to
// the legacy users.media_uuid if no identity exists yet. It also unseals the
// token when present.
func getUserByUUIDPreferred(uuid string) (User, error) {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    var row User
    err := db.QueryRowContext(ctx, `
        SELECT u.id, u.username, u.email, i.media_uuid, i.media_token, i.media_access
          FROM identities i
          JOIN users u ON u.id = i.user_id
         WHERE i.media_uuid = $1
         LIMIT 1
    `, uuid).Scan(
        &row.ID,
        &row.Username,
        &row.Email,
        &row.MediaUUID,
        &row.MediaToken,
        &row.MediaAccess,
    )
    if err == nil {
        if row.MediaToken.Valid && row.MediaToken.String != "" {
            if pt, decErr := unsealToken(row.MediaToken.String); decErr == nil {
                row.MediaToken = sql.NullString{String: pt, Valid: true}
            } else {
                row.MediaToken = sql.NullString{}
            }
        }
        return row, nil
    }
    if err != sql.ErrNoRows {
        return User{}, err
    }
    // Fallback to legacy users table
    return getUserByUUID(uuid)
}

// Identity describes a provider-bound identity for a user.
type Identity struct {
    UserID      int
    Provider    string
    MediaUUID   string
    MediaToken  sql.NullString
    MediaAccess bool
}

// getUserIdentities returns all provider identities for a given user id.
func getUserIdentities(userID int) ([]Identity, error) {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    rows, err := db.QueryContext(ctx, `
        SELECT user_id, provider, media_uuid, media_token, media_access
          FROM identities
         WHERE user_id = $1
         ORDER BY provider
    `, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []Identity
    for rows.Next() {
        var id Identity
        if err := rows.Scan(&id.UserID, &id.Provider, &id.MediaUUID, &id.MediaToken, &id.MediaAccess); err != nil {
            return nil, err
        }
        out = append(out, id)
    }
    return out, rows.Err()
}

// getIdentityByProviderUUID fetches one identity by provider and media uuid.
func getIdentityByProviderUUID(provider, mediaUUID string) (Identity, error) {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()
    var id Identity
    err := db.QueryRowContext(ctx, `
        SELECT user_id, provider, media_uuid, media_token, media_access
          FROM identities
         WHERE provider = $1 AND media_uuid = $2
         LIMIT 1
    `, strings.TrimSpace(provider), strings.TrimSpace(mediaUUID)).Scan(
        &id.UserID, &id.Provider, &id.MediaUUID, &id.MediaToken, &id.MediaAccess,
    )
    if err != nil {
        return Identity{}, err
    }
    return id, nil
}

// upsertUserIdentity ensures a user row exists (by username) and then
// upserts a provider-specific identity row. It keeps the legacy users
// table in sync by calling upsertUser with the same data for backwards
// compatibility.
func upsertUserIdentity(username, email, provider, mediaUUID, mediaToken string, access bool) (int, error) {
    // First, upsert legacy user record (keeps existing flows working)
    uid, err := upsertUser(User{
        Username:    username,
        Email:       nullStringFrom(email),
        MediaUUID:   nullStringFrom(mediaUUID),
        MediaToken:  nullStringFrom(mediaToken),
        MediaAccess: access,
    })
    if err != nil {
        return 0, err
    }

    // Then, upsert identities row
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    // Insert or update on provider+media_uuid
    _, err = db.ExecContext(ctx, `
INSERT INTO identities (user_id, provider, media_uuid, media_token, media_access)
VALUES ($1, $2, $3, NULLIF($4, ''), $5)
ON CONFLICT (provider, media_uuid) DO UPDATE
   SET user_id      = EXCLUDED.user_id,
       media_token  = COALESCE(NULLIF(EXCLUDED.media_token, ''), identities.media_token),
       media_access = EXCLUDED.media_access,
       updated_at   = now()
`, uid, strings.TrimSpace(provider), strings.TrimSpace(mediaUUID), strings.TrimSpace(mediaToken), access)
    if err != nil {
        return 0, err
    }
    return uid, nil
}
