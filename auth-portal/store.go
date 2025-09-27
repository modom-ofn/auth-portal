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


// MFARecord captures the stored MFA configuration for a user.
type MFARecord struct {
    UserID        int
    SecretEnc     sql.NullString
    SecretAlgo    string
    Digits        int
    PeriodSeconds int
    DriftSteps    int
    IsVerified    bool
    IssuedAt      time.Time
    VerifiedAt    sql.NullTime
    LastUsedAt    sql.NullTime
    CreatedAt     time.Time
    UpdatedAt     time.Time
}

func getMFARecord(userID int) (MFARecord, error) {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    var rec MFARecord
    err := db.QueryRowContext(ctx, `
SELECT user_id, secret_enc, secret_algo, digits, period_seconds, drift_steps,
       is_verified, issued_at, verified_at, last_used_at, created_at, updated_at
  FROM user_mfa
 WHERE user_id = $1
`, userID).Scan(
        &rec.UserID,
        &rec.SecretEnc,
        &rec.SecretAlgo,
        &rec.Digits,
        &rec.PeriodSeconds,
        &rec.DriftSteps,
        &rec.IsVerified,
        &rec.IssuedAt,
        &rec.VerifiedAt,
        &rec.LastUsedAt,
        &rec.CreatedAt,
        &rec.UpdatedAt,
    )
    if err != nil {
        return MFARecord{}, err
    }
    return rec, nil
}

// beginMFAEnrollment stores a new sealed secret for the user and resets MFA state.
func beginMFAEnrollment(userID int, sealedSecret string, algo string, digits, period, drift int) error {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    if _, err = tx.ExecContext(ctx, `
INSERT INTO user_mfa (user_id, secret_enc, secret_algo, digits, period_seconds, drift_steps,
                      is_verified, issued_at, verified_at, last_used_at, created_at, updated_at)
VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, FALSE, now(), NULL, NULL, now(), now())
ON CONFLICT (user_id) DO UPDATE
   SET secret_enc     = NULLIF(EXCLUDED.secret_enc, ''),
       secret_algo    = EXCLUDED.secret_algo,
       digits         = EXCLUDED.digits,
       period_seconds = EXCLUDED.period_seconds,
       drift_steps    = EXCLUDED.drift_steps,
       is_verified    = FALSE,
       issued_at      = now(),
       verified_at    = NULL,
       last_used_at   = NULL,
       updated_at     = now()
`, userID, strings.TrimSpace(sealedSecret), strings.TrimSpace(algo), digits, period, drift); err != nil {
        return err
    }

    if _, err = tx.ExecContext(ctx, `
DELETE FROM user_mfa_recovery_codes
 WHERE user_id = $1
`, userID); err != nil {
        return err
    }

    if _, err = tx.ExecContext(ctx, `
UPDATE users
   SET mfa_enabled = FALSE,
       mfa_enrolled_at = NULL,
       mfa_recovery_last_rotated = NULL
 WHERE id = $1
`, userID); err != nil {
        return err
    }

    return tx.Commit()
}

// markMFASecretVerified flags the stored MFA secret as verified and enables MFA.
func markMFASecretVerified(userID int) error {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    res, err := tx.ExecContext(ctx, `
UPDATE user_mfa
   SET is_verified = TRUE,
       verified_at = now(),
       updated_at  = now()
 WHERE user_id = $1
`, userID)
    if err != nil {
        return err
    }
    rows, err := res.RowsAffected()
    if err != nil {
        return err
    }
    if rows == 0 {
        return sql.ErrNoRows
    }

    if _, err = tx.ExecContext(ctx, `
UPDATE users
   SET mfa_enabled = TRUE,
       mfa_enrolled_at = COALESCE(mfa_enrolled_at, now())
 WHERE id = $1
`, userID); err != nil {
        return err
    }

    return tx.Commit()
}

// replaceMFARecoveryCodes swaps in a new set of hashed recovery codes for the user.
func replaceMFARecoveryCodes(userID int, hashedCodes []string) error {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    if _, err = tx.ExecContext(ctx, `
DELETE FROM user_mfa_recovery_codes
 WHERE user_id = $1
`, userID); err != nil {
        return err
    }

    for _, hash := range hashedCodes {
        hash = strings.TrimSpace(hash)
        if hash == "" {
            continue
        }
        if _, err = tx.ExecContext(ctx, `
INSERT INTO user_mfa_recovery_codes (user_id, code_hash)
VALUES ($1, $2)
ON CONFLICT (user_id, code_hash) DO NOTHING
`, userID, hash); err != nil {
            return err
        }
    }

    if _, err = tx.ExecContext(ctx, `
UPDATE users
   SET mfa_recovery_last_rotated = now()
 WHERE id = $1
`, userID); err != nil {
        return err
    }

    return tx.Commit()
}

// consumeMFARecoveryCode marks a recovery code as used. It returns true when a code was consumed.
func consumeMFARecoveryCode(userID int, hash string) (bool, error) {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    res, err := db.ExecContext(ctx, `
UPDATE user_mfa_recovery_codes
   SET used_at = now()
 WHERE user_id = $1
   AND code_hash = $2
   AND used_at IS NULL
`, userID, strings.TrimSpace(hash))
    if err != nil {
        return false, err
    }
    rows, err := res.RowsAffected()
    if err != nil {
        return false, err
    }
    return rows > 0, nil
}

// countUnusedMFARecoveryCodes returns the number of remaining (unused) recovery codes.
func countUnusedMFARecoveryCodes(userID int) (int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
    defer cancel()

    var count int
    err := db.QueryRowContext(ctx, `
        SELECT COUNT(*)
          FROM user_mfa_recovery_codes
         WHERE user_id = $1
           AND used_at IS NULL
    `, userID).Scan(&count)
    if err != nil {
        return 0, err
    }
    return count, nil
}
