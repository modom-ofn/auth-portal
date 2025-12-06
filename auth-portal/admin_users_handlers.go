package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lib/pq"
)

type adminUserIdentity struct {
	Provider    string `json:"provider"`
	MediaUUID   string `json:"mediaUuid,omitempty"`
	MediaAccess bool   `json:"mediaAccess"`
}

type adminUser struct {
	ID                     int                 `json:"id"`
	Username               string              `json:"username"`
	Email                  string              `json:"email,omitempty"`
	MediaUUID              string              `json:"mediaUuid,omitempty"`
	MediaAccess            bool                `json:"mediaAccess"`
	Providers              []adminUserIdentity `json:"providers,omitempty"`
	IsAdmin                bool                `json:"isAdmin"`
	AdminGrantedAt         *time.Time          `json:"adminGrantedAt,omitempty"`
	AdminGrantedBy         string              `json:"adminGrantedBy,omitempty"`
	MFAEnabled             bool                `json:"mfaEnabled"`
	MFAEnrolledAt          *time.Time          `json:"mfaEnrolledAt,omitempty"`
	MFARecoveryLastRotated *time.Time          `json:"mfaRecoveryLastRotated,omitempty"`
	MFALastUsedAt          *time.Time          `json:"mfaLastUsedAt,omitempty"`
	LastSeenAt             *time.Time          `json:"lastSeenAt,omitempty"`
	CreatedAt              time.Time           `json:"createdAt"`
	UpdatedAt              time.Time           `json:"updatedAt"`
	RecoveryCodesRemaining int                 `json:"recoveryCodesRemaining,omitempty"`
}

type adminUsersResponse struct {
	OK    bool        `json:"ok"`
	Users []adminUser `json:"users"`
}

func adminUsersListHandler(w http.ResponseWriter, r *http.Request) {
	users, err := loadAdminUsers(r.Context())
	if err != nil {
		log.Printf("admin users list failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "user list failed"})
		return
	}
	respondJSON(w, http.StatusOK, adminUsersResponse{
		OK:    true,
		Users: users,
	})
}

type adminUserRow struct {
	ID                     int
	Username               string
	Email                  sql.NullString
	MediaUUID              sql.NullString
	MediaAccess            bool
	IsAdmin                bool
	AdminGrantedAt         sql.NullTime
	AdminGrantedBy         sql.NullString
	MFAEnabled             bool
	MFAEnrolledAt          sql.NullTime
	MFARecoveryLastRotated sql.NullTime
	CreatedAt              time.Time
	UpdatedAt              time.Time
	LastSeenAt             sql.NullTime
	MFALastUsedAt          sql.NullTime
}

func loadAdminUsers(ctx context.Context) ([]adminUser, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT u.id, u.username, u.email, u.media_uuid, u.media_access, u.is_admin,
       u.admin_granted_at, u.admin_granted_by,
       u.mfa_enabled, u.mfa_enrolled_at, u.mfa_recovery_last_rotated,
       u.created_at, u.updated_at, u.last_seen_at,
       m.last_used_at
  FROM users u
  LEFT JOIN user_mfa m ON m.user_id = u.id
 ORDER BY lower(u.username), u.id
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		users   []adminUser
		userIDs []int
	)

	for rows.Next() {
		var row adminUserRow
		if scanErr := rows.Scan(
			&row.ID,
			&row.Username,
			&row.Email,
			&row.MediaUUID,
			&row.MediaAccess,
			&row.IsAdmin,
			&row.AdminGrantedAt,
			&row.AdminGrantedBy,
			&row.MFAEnabled,
			&row.MFAEnrolledAt,
			&row.MFARecoveryLastRotated,
			&row.CreatedAt,
			&row.UpdatedAt,
			&row.LastSeenAt,
			&row.MFALastUsedAt,
		); scanErr != nil {
			return nil, scanErr
		}

		userIDs = append(userIDs, row.ID)
		users = append(users, adminUser{
			ID:                     row.ID,
			Username:               strings.TrimSpace(row.Username),
			Email:                  trimNullString(row.Email),
			MediaUUID:              trimNullString(row.MediaUUID),
			MediaAccess:            row.MediaAccess,
			IsAdmin:                row.IsAdmin,
			AdminGrantedAt:         timePtr(row.AdminGrantedAt),
			AdminGrantedBy:         trimNullString(row.AdminGrantedBy),
			MFAEnabled:             row.MFAEnabled,
			MFAEnrolledAt:          timePtr(row.MFAEnrolledAt),
			MFARecoveryLastRotated: timePtr(row.MFARecoveryLastRotated),
			MFALastUsedAt:          timePtr(row.MFALastUsedAt),
			LastSeenAt:             timePtr(row.LastSeenAt),
			CreatedAt:              row.CreatedAt.UTC(),
			UpdatedAt:              row.UpdatedAt.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	identityMap, err := loadAdminUserIdentities(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	recoveryCounts, err := loadAdminRecoveryCounts(ctx, userIDs)
	if err != nil {
		return nil, err
	}

	for i := range users {
		u := &users[i]
		u.Providers = identityMap[u.ID]
		if len(u.Providers) == 0 && u.MediaUUID != "" {
			provider := strings.TrimSpace(mediaProviderKey)
			if provider == "" && currentProvider != nil {
				provider = strings.TrimSpace(currentProvider.Name())
			}
			if provider == "" {
				provider = "media"
			}
			u.Providers = []adminUserIdentity{{
				Provider:    provider,
				MediaUUID:   u.MediaUUID,
				MediaAccess: u.MediaAccess,
			}}
		}
		if remaining, ok := recoveryCounts[u.ID]; ok && remaining > 0 {
			u.RecoveryCodesRemaining = remaining
		}
	}

	return users, nil
}

func loadAdminUserIdentities(ctx context.Context, userIDs []int) (map[int][]adminUserIdentity, error) {
	result := make(map[int][]adminUserIdentity, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}

	rows, err := db.QueryContext(ctx, `
SELECT user_id, provider, media_uuid, media_access
  FROM identities
 WHERE user_id = ANY($1)
 ORDER BY provider
`, pq.Array(userIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			userID int
			prov   string
			uuid   sql.NullString
			access bool
		)
		if scanErr := rows.Scan(&userID, &prov, &uuid, &access); scanErr != nil {
			return nil, scanErr
		}
		result[userID] = append(result[userID], adminUserIdentity{
			Provider:    strings.TrimSpace(prov),
			MediaUUID:   trimNullString(uuid),
			MediaAccess: access,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func loadAdminRecoveryCounts(ctx context.Context, userIDs []int) (map[int]int, error) {
	result := make(map[int]int, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}

	rows, err := db.QueryContext(ctx, `
SELECT user_id, COUNT(*) FILTER (WHERE used_at IS NULL) AS remaining
  FROM user_mfa_recovery_codes
 WHERE user_id = ANY($1)
 GROUP BY user_id
`, pq.Array(userIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var userID, remaining int
		if scanErr := rows.Scan(&userID, &remaining); scanErr != nil {
			return nil, scanErr
		}
		result[userID] = remaining
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func trimNullString(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return strings.TrimSpace(ns.String)
}

func timePtr(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time.UTC()
	return &t
}
