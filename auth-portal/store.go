package main

import (
	"context"
	"database/sql"
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