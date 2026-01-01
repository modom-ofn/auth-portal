package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
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
	Roles                  []string            `json:"roles,omitempty"`
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

type adminUserDeleteRequest struct {
	Reason string `json:"reason"`
}

type adminUserDeleteResponse struct {
	OK        bool   `json:"ok"`
	DeletedID int    `json:"deletedId"`
	Username  string `json:"username"`
}

type adminUserBulkDeleteResponse struct {
	OK            bool      `json:"ok"`
	DeletedCount  int       `json:"deletedCount"`
	EligibleCount int       `json:"eligibleCount"`
	Cutoff        time.Time `json:"cutoff"`
}

type adminUserDeleteAudit struct {
	UserID      int                 `json:"userId"`
	Username    string              `json:"username"`
	Email       string              `json:"email,omitempty"`
	MediaUUID   string              `json:"mediaUuid,omitempty"`
	MediaAccess bool                `json:"mediaAccess"`
	IsAdmin     bool                `json:"isAdmin"`
	Roles       []string            `json:"roles,omitempty"`
	Providers   []adminUserIdentity `json:"providers,omitempty"`
	CreatedAt   time.Time           `json:"createdAt"`
	UpdatedAt   time.Time           `json:"updatedAt"`
	LastSeenAt  *time.Time          `json:"lastSeenAt,omitempty"`
}

func adminUserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(strings.TrimSpace(idStr))
	if err != nil || id <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	var req adminUserDeleteRequest
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		http.Error(w, "delete reason required", http.StatusBadRequest)
		return
	}

	actor := strings.TrimSpace(usernameFrom(r.Context()))
	if actor == "" {
		actor = strings.TrimSpace(uuidFrom(r.Context()))
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var (
		userID      int
		username    string
		email       sql.NullString
		mediaUUID   sql.NullString
		mediaAccess bool
		isAdmin     bool
		createdAt   time.Time
		updatedAt   time.Time
		lastSeenAt  sql.NullTime
	)
	row := tx.QueryRowContext(ctx, `
SELECT id, username, email, media_uuid, media_access, is_admin, created_at, updated_at, last_seen_at
  FROM users
 WHERE id = $1
 FOR UPDATE
`, id)
	if err := row.Scan(&userID, &username, &email, &mediaUUID, &mediaAccess, &isAdmin, &createdAt, &updatedAt, &lastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}

	if mediaAccess || isAdmin {
		http.Error(w, "only unauthorized/guest users can be deleted", http.StatusBadRequest)
		return
	}

	roles, err := loadUserRolesForAudit(ctx, tx, userID)
	if err != nil {
		http.Error(w, "role lookup failed", http.StatusInternalServerError)
		return
	}
	providers, err := loadUserProvidersForAudit(ctx, tx, userID)
	if err != nil {
		http.Error(w, "identity lookup failed", http.StatusInternalServerError)
		return
	}
	if len(providers) == 0 && trimNullString(mediaUUID) != "" {
		provider := strings.TrimSpace(mediaProviderKey)
		if provider == "" && currentProvider != nil {
			provider = strings.TrimSpace(currentProvider.Name())
		}
		if provider == "" {
			provider = "media"
		}
		providers = []adminUserIdentity{{
			Provider:    provider,
			MediaUUID:   trimNullString(mediaUUID),
			MediaAccess: mediaAccess,
		}}
	}

	audit := adminUserDeleteAudit{
		UserID:      userID,
		Username:    strings.TrimSpace(username),
		Email:       trimNullString(email),
		MediaUUID:   trimNullString(mediaUUID),
		MediaAccess: mediaAccess,
		IsAdmin:     isAdmin,
		Roles:       roles,
		Providers:   providers,
		CreatedAt:   createdAt.UTC(),
		UpdatedAt:   updatedAt.UTC(),
		LastSeenAt:  timePtr(lastSeenAt),
	}
	meta, err := json.Marshal(audit)
	if err != nil {
		http.Error(w, "audit encoding failed", http.StatusInternalServerError)
		return
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO admin_audit_events (action, target_type, target_id, target_label, actor, reason, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, "user.delete", "user", userID, strings.TrimSpace(username), actor, reason, meta); err != nil {
		http.Error(w, "audit write failed", http.StatusInternalServerError)
		return
	}

	res, err := tx.ExecContext(ctx, `
DELETE FROM users
 WHERE id = $1
`, userID)
	if err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		http.Error(w, "delete failed", http.StatusConflict)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, adminUserDeleteResponse{
		OK:        true,
		DeletedID: userID,
		Username:  strings.TrimSpace(username),
	})
}

type adminUserBulkDeleteAudit struct {
	DeletedCount int                    `json:"deletedCount"`
	Cutoff       time.Time              `json:"cutoff"`
	MinAge       string                 `json:"minAge"`
	Users        []adminUserDeleteAudit `json:"users"`
}

func adminUsersBulkDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var req adminUserDeleteRequest
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		http.Error(w, "delete reason required", http.StatusBadRequest)
		return
	}

	actor := strings.TrimSpace(usernameFrom(r.Context()))
	if actor == "" {
		actor = strings.TrimSpace(uuidFrom(r.Context()))
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	cutoff := time.Now().UTC().Add(-guestBulkDeleteMinAge)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, `
SELECT id, username, email, media_uuid, media_access, is_admin, created_at, updated_at, last_seen_at
  FROM users
 WHERE media_access = false AND is_admin = false AND created_at <= $1
 FOR UPDATE
`, cutoff)
	if err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var audits []adminUserDeleteAudit
	for rows.Next() {
		var (
			userID      int
			username    string
			email       sql.NullString
			mediaUUID   sql.NullString
			mediaAccess bool
			isAdmin     bool
			createdAt   time.Time
			updatedAt   time.Time
			lastSeenAt  sql.NullTime
		)
		if err := rows.Scan(&userID, &username, &email, &mediaUUID, &mediaAccess, &isAdmin, &createdAt, &updatedAt, &lastSeenAt); err != nil {
			http.Error(w, "user lookup failed", http.StatusInternalServerError)
			return
		}
		audits = append(audits, adminUserDeleteAudit{
			UserID:      userID,
			Username:    strings.TrimSpace(username),
			Email:       trimNullString(email),
			MediaUUID:   trimNullString(mediaUUID),
			MediaAccess: mediaAccess,
			IsAdmin:     isAdmin,
			CreatedAt:   createdAt.UTC(),
			UpdatedAt:   updatedAt.UTC(),
			LastSeenAt:  timePtr(lastSeenAt),
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}

	if len(audits) == 0 {
		respondJSON(w, http.StatusOK, adminUserBulkDeleteResponse{
			OK:            true,
			DeletedCount:  0,
			EligibleCount: 0,
			Cutoff:        cutoff,
		})
		return
	}

	meta, err := json.Marshal(adminUserBulkDeleteAudit{
		DeletedCount: len(audits),
		Cutoff:       cutoff,
		MinAge:       guestBulkDeleteMinAge.String(),
		Users:        audits,
	})
	if err != nil {
		http.Error(w, "audit encoding failed", http.StatusInternalServerError)
		return
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO admin_audit_events (action, target_type, target_label, actor, reason, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
`, "user.delete.bulk", "user", "unauthorized", actor, reason, meta); err != nil {
		http.Error(w, "audit write failed", http.StatusInternalServerError)
		return
	}

	res, err := tx.ExecContext(ctx, `
DELETE FROM users
 WHERE media_access = false AND is_admin = false AND created_at <= $1
`, cutoff)
	if err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	deleted, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, adminUserBulkDeleteResponse{
		OK:            true,
		DeletedCount:  int(deleted),
		EligibleCount: len(audits),
		Cutoff:        cutoff,
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
	roleMap, err := loadAdminUserRoles(ctx, userIDs)
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
		u.Roles = roleMap[u.ID]
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

func loadAdminUserRoles(ctx context.Context, userIDs []int) (map[int][]string, error) {
	result := make(map[int][]string, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}

	rows, err := db.QueryContext(ctx, `
SELECT ur.user_id, r.name
  FROM user_roles ur
  JOIN roles r ON r.id = ur.role_id
 WHERE ur.user_id = ANY($1)
 ORDER BY lower(r.name)
`, pq.Array(userIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var userID int
		var role string
		if err := rows.Scan(&userID, &role); err != nil {
			return nil, err
		}
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		result[userID] = append(result[userID], role)
	}
	return result, rows.Err()
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

func loadUserRolesForAudit(ctx context.Context, tx *sql.Tx, userID int) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT r.name
  FROM user_roles ur
  JOIN roles r ON r.id = ur.role_id
 WHERE ur.user_id = $1
 ORDER BY lower(r.name)
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

func loadUserProvidersForAudit(ctx context.Context, tx *sql.Tx, userID int) ([]adminUserIdentity, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT provider, media_uuid, media_access
  FROM identities
 WHERE user_id = $1
 ORDER BY provider
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []adminUserIdentity
	for rows.Next() {
		var (
			prov   string
			uuid   sql.NullString
			access bool
		)
		if err := rows.Scan(&prov, &uuid, &access); err != nil {
			return nil, err
		}
		out = append(out, adminUserIdentity{
			Provider:    strings.TrimSpace(prov),
			MediaUUID:   trimNullString(uuid),
			MediaAccess: access,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
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
