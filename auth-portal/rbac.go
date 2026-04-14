package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	roleAdmin  = "admin"
	roleViewer = "viewer"
	roleUser   = "user"

	permissionAdminAccess  = "admin.access"
	permissionConfigRead   = "config.read"
	permissionConfigWrite  = "config.write"
	permissionOAuthRead    = "oauth.read"
	permissionOAuthWrite   = "oauth.write"
	permissionBackupsRead  = "backups.read"
	permissionBackupsWrite = "backups.write"
	permissionLDAPRead     = "ldap.read"
	permissionLDAPWrite    = "ldap.write"
	permissionRBACRead     = "rbac.read"
	permissionRBACWrite    = "rbac.write"
	permissionPortalAccess = "portal.access"

	errUnknownRoleFormat       = "unknown role %q"
	errUnknownPermissionFormat = "unknown permission %q"
)

var seededRolePermissions = map[string][]string{
	roleAdmin: {
		permissionAdminAccess,
		permissionConfigRead,
		permissionConfigWrite,
		permissionOAuthRead,
		permissionOAuthWrite,
		permissionBackupsRead,
		permissionBackupsWrite,
		permissionLDAPRead,
		permissionLDAPWrite,
		permissionRBACRead,
		permissionRBACWrite,
		permissionPortalAccess,
	},
	roleViewer: {
		permissionAdminAccess,
		permissionConfigRead,
		permissionOAuthRead,
		permissionBackupsRead,
		permissionLDAPRead,
		permissionRBACRead,
		permissionPortalAccess,
	},
	roleUser: {
		permissionPortalAccess,
	},
}

type RoleAssignment struct {
	Role          string    `json:"role"`
	Source        string    `json:"source"`
	ExternalRef   string    `json:"externalRef,omitempty"`
	GrantedBy     string    `json:"grantedBy,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	Manual        bool      `json:"manual"`
	PermissionSet []string  `json:"permissionSet,omitempty"`
}

type RoleDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
	System      bool     `json:"system"`
}

type PermissionDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	System      bool   `json:"system"`
}

type UserRoleBinding struct {
	UserID          int              `json:"userId"`
	Username        string           `json:"username"`
	Email           string           `json:"email,omitempty"`
	IsAdmin         bool             `json:"isAdmin"`
	ManualRoles     []string         `json:"manualRoles"`
	EffectiveRoles  []string         `json:"effectiveRoles"`
	Permissions     []string         `json:"permissions"`
	RoleAssignments []RoleAssignment `json:"roleAssignments"`
}

type bindingState struct {
	item UserRoleBinding
}

func normalizeRBACName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeRBACSource(value string) string {
	value = normalizeRBACName(value)
	if value == "" {
		return "manual"
	}
	return value
}

func roleAssignmentSource(grantedBy string) string {
	switch strings.ToLower(strings.TrimSpace(grantedBy)) {
	case "", "admin", "manual":
		return "manual"
	case "provider-sync":
		return "provider-sync"
	case "system:bootstrap":
		return "bootstrap"
	default:
		return normalizeRBACSource(grantedBy)
	}
}

func requirePermission(permission string, next http.Handler) http.Handler {
	return requireAnyPermission([]string{permission}, next)
}

func requireAnyPermission(permissions []string, next http.Handler) http.Handler {
	normalized := normalizePermissionList(permissions)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, uuid, ok := requirePermissionIdentity(w, r)
		if !ok {
			return
		}

		granted, adminAccess, err := userHasAnyPermission(uuid, username, normalized)
		if err != nil {
			log.Printf("requirePermission: permission lookup failed for %s (%s): %v", username, uuid, err)
			http.Error(w, "permission verification failed", http.StatusInternalServerError)
			return
		}
		if !granted {
			denyPermissionRequest(w, r, normalized)
			return
		}

		if adminAccess && !adminFrom(r.Context()) {
			r = r.WithContext(withAdmin(r.Context(), true))
		}
		next.ServeHTTP(w, r)
	})
}

func requirePermissionIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if !hasValidSession(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return "", "", false
	}
	username := strings.TrimSpace(usernameFrom(r.Context()))
	uuid := strings.TrimSpace(uuidFrom(r.Context()))
	if username == "" && uuid == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return "", "", false
	}
	return username, uuid, true
}

func denyPermissionRequest(w http.ResponseWriter, r *http.Request, permissions []string) {
	msg := "permission required"
	if len(permissions) == 1 {
		msg = permissions[0] + " permission required"
	}
	if prefersJSON(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": msg})
		return
	}
	http.Error(w, msg, http.StatusForbidden)
}

func normalizePermissionList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalizeRBACName(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeDistinctStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isSystemRole(roleName string) bool {
	switch normalizeRBACName(roleName) {
	case roleAdmin, roleViewer, roleUser:
		return true
	default:
		return false
	}
}

func isSystemPermission(permissionName string) bool {
	switch normalizeRBACName(permissionName) {
	case permissionAdminAccess,
		permissionConfigRead,
		permissionConfigWrite,
		permissionOAuthRead,
		permissionOAuthWrite,
		permissionBackupsRead,
		permissionBackupsWrite,
		permissionLDAPRead,
		permissionLDAPWrite,
		permissionRBACRead,
		permissionRBACWrite,
		permissionPortalAccess:
		return true
	default:
		return false
	}
}

func listPermissionDefinitions() ([]PermissionDefinition, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT name, COALESCE(description, '')
  FROM permissions
 ORDER BY name
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PermissionDefinition
	for rows.Next() {
		var (
			name        string
			description string
		)
		if err := rows.Scan(&name, &description); err != nil {
			return nil, err
		}
		out = append(out, PermissionDefinition{
			Name:        normalizeRBACName(name),
			Description: strings.TrimSpace(description),
			System:      isSystemPermission(name),
		})
	}
	return out, rows.Err()
}

func listPermissionNames() ([]string, error) {
	defs, err := listPermissionDefinitions()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(defs))
	for _, def := range defs {
		out = append(out, def.Name)
	}
	return out, nil
}

func listRolePermissionMap() (map[string][]string, error) {
	defs, err := listRoleDefinitions()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(defs))
	for _, def := range defs {
		out[def.Name] = append([]string{}, def.Permissions...)
	}
	return out, nil
}

func userRoles(uuid, username string) ([]string, error) {
	assignments, err := userRoleAssignments(uuid, username)
	if err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		roles = append(roles, assignment.Role)
	}
	return normalizeDistinctStrings(roles), nil
}

func userRoleAssignments(uuid, username string) ([]RoleAssignment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	userID, err := resolveUserID(ctx, uuid, username)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT r.name, ur.source, ur.external_ref, ur.granted_by, ur.created_at, ur.updated_at
  FROM user_roles ur
  JOIN roles r ON r.id = ur.role_id
 WHERE ur.user_id = $1
 ORDER BY r.name, ur.source, ur.external_ref
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assignments := []RoleAssignment{}
	for rows.Next() {
		var (
			item        RoleAssignment
			externalRef string
			grantedBy   sql.NullString
		)
		if err := rows.Scan(&item.Role, &item.Source, &externalRef, &grantedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Role = normalizeRBACName(item.Role)
		item.Source = normalizeRBACSource(item.Source)
		item.ExternalRef = strings.TrimSpace(externalRef)
		if grantedBy.Valid {
			item.GrantedBy = strings.TrimSpace(grantedBy.String)
		}
		item.Manual = item.Source == "manual" || item.Source == "bootstrap"
		assignments = append(assignments, item)
	}
	return assignments, rows.Err()
}

func listRoleDefinitions() ([]RoleDefinition, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT r.name, COALESCE(r.description, ''), p.name
  FROM roles r
  LEFT JOIN role_permissions rp ON rp.role_id = r.id
  LEFT JOIN permissions p ON p.id = rp.permission_id
 ORDER BY r.name, p.name
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roleMap := make(map[string]*RoleDefinition)
	order := []string{}
	for rows.Next() {
		var (
			roleName    string
			description string
			permission  sql.NullString
		)
		if err := rows.Scan(&roleName, &description, &permission); err != nil {
			return nil, err
		}
		def := roleMap[roleName]
		if def == nil {
			def = &RoleDefinition{
				Name:        normalizeRBACName(roleName),
				Description: strings.TrimSpace(description),
				System:      isSystemRole(roleName),
			}
			roleMap[roleName] = def
			order = append(order, roleName)
		}
		if permission.Valid {
			def.Permissions = append(def.Permissions, normalizeRBACName(permission.String))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]RoleDefinition, 0, len(order))
	for _, name := range order {
		def := roleMap[name]
		def.Permissions = normalizeDistinctStrings(def.Permissions)
		out = append(out, *def)
	}
	return out, nil
}

func listUserRoleBindings() ([]UserRoleBinding, error) {
	rolePermissions, err := listRolePermissionMap()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT u.id, u.username, COALESCE(u.email, ''), u.is_admin,
       COALESCE(r.name, ''), COALESCE(ur.source, ''), COALESCE(ur.external_ref, ''), COALESCE(ur.granted_by, ''),
       ur.created_at, ur.updated_at
  FROM users u
  LEFT JOIN user_roles ur ON ur.user_id = u.id
  LEFT JOIN roles r ON r.id = ur.role_id
 WHERE u.username <> ''
 ORDER BY u.username, r.name, ur.source, ur.external_ref
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userMap := make(map[int]*bindingState)
	order := []int{}
	for rows.Next() {
		record, err := scanUserRoleBindingRecord(rows)
		if err != nil {
			return nil, err
		}
		state, created := ensureBindingState(userMap, record)
		if created {
			order = append(order, record.userID)
		}
		appendRoleAssignment(state, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]UserRoleBinding, 0, len(order))
	for _, userID := range order {
		out = append(out, finalizeUserRoleBinding(userMap[userID].item, rolePermissions))
	}
	return out, nil
}

type userRoleBindingRecord struct {
	userID      int
	username    string
	email       string
	isAdmin     bool
	roleName    string
	source      string
	externalRef string
	grantedBy   string
	createdAt   sql.NullTime
	updatedAt   sql.NullTime
}

func scanUserRoleBindingRecord(rows *sql.Rows) (userRoleBindingRecord, error) {
	var record userRoleBindingRecord
	err := rows.Scan(
		&record.userID,
		&record.username,
		&record.email,
		&record.isAdmin,
		&record.roleName,
		&record.source,
		&record.externalRef,
		&record.grantedBy,
		&record.createdAt,
		&record.updatedAt,
	)
	return record, err
}

func ensureBindingState(userMap map[int]*bindingState, record userRoleBindingRecord) (*bindingState, bool) {
	state, ok := userMap[record.userID]
	if ok {
		return state, false
	}
	state = &bindingState{
		item: UserRoleBinding{
			UserID:      record.userID,
			Username:    strings.TrimSpace(record.username),
			Email:       strings.TrimSpace(record.email),
			IsAdmin:     record.isAdmin,
			ManualRoles: []string{},
		},
	}
	userMap[record.userID] = state
	return state, true
}

func appendRoleAssignment(state *bindingState, record userRoleBindingRecord) {
	roleName := normalizeRBACName(record.roleName)
	if roleName == "" {
		return
	}
	source := normalizeRBACSource(record.source)
	assignment := RoleAssignment{
		Role:        roleName,
		Source:      source,
		ExternalRef: strings.TrimSpace(record.externalRef),
		GrantedBy:   strings.TrimSpace(record.grantedBy),
		Manual:      source == "manual" || source == "bootstrap",
	}
	if record.createdAt.Valid {
		assignment.CreatedAt = record.createdAt.Time.UTC()
	}
	if record.updatedAt.Valid {
		assignment.UpdatedAt = record.updatedAt.Time.UTC()
	}
	state.item.RoleAssignments = append(state.item.RoleAssignments, assignment)
	if assignment.Manual {
		state.item.ManualRoles = append(state.item.ManualRoles, roleName)
	}
}

func finalizeUserRoleBinding(item UserRoleBinding, rolePermissions map[string][]string) UserRoleBinding {
	effectiveRoles := make([]string, 0, len(item.RoleAssignments))
	for idx := range item.RoleAssignments {
		item.RoleAssignments[idx].PermissionSet = append([]string{}, rolePermissions[item.RoleAssignments[idx].Role]...)
		effectiveRoles = append(effectiveRoles, item.RoleAssignments[idx].Role)
	}
	item.ManualRoles = normalizeDistinctStrings(item.ManualRoles)
	item.EffectiveRoles = normalizeDistinctStrings(effectiveRoles)
	permissionSet := make([]string, 0)
	for _, role := range item.EffectiveRoles {
		permissionSet = append(permissionSet, rolePermissions[role]...)
	}
	item.Permissions = normalizePermissionList(permissionSet)
	return item
}

func replaceManualRolesByUsername(username string, roles []string, grantedBy string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username required")
	}
	roles = normalizePermissionList(roles)

	if err := validateRoleNames(roles); err != nil {
		return err
	}
	if _, err := upsertUser(User{Username: username}); err != nil {
		return err
	}
	current, err := listManualRolesByUsername(username)
	if err != nil {
		return err
	}
	return applyManualRoleChanges(username, current, roles, grantedBy)
}

func upsertRoleDefinition(currentName string, def RoleDefinition) error {
	currentName = normalizeRBACName(currentName)
	def.Name = normalizeRBACName(def.Name)
	def.Description = strings.TrimSpace(def.Description)
	def.Permissions = normalizePermissionList(def.Permissions)

	if def.Name == "" {
		return errors.New("role name required")
	}
	if len(def.Permissions) == 0 {
		return errors.New("at least one permission is required")
	}
	if currentName != "" && isSystemRole(currentName) {
		return errors.New("system roles cannot be modified")
	}
	if currentName == "" && isSystemRole(def.Name) {
		return errors.New("system roles already exist and cannot be recreated")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := validatePermissionNamesTx(ctx, tx, def.Permissions); err != nil {
		return err
	}
	roleID, err := upsertRoleRecordTx(ctx, tx, currentName, def)
	if err != nil {
		return err
	}
	if err := replaceRolePermissionsTx(ctx, tx, roleID, def.Permissions); err != nil {
		return err
	}
	return tx.Commit()
}

func deleteRoleDefinition(roleName string) error {
	roleName = normalizeRBACName(roleName)
	if roleName == "" {
		return errors.New("role required")
	}
	if isSystemRole(roleName) {
		return errors.New("system roles cannot be deleted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
SELECT DISTINCT ur.user_id
  FROM user_roles ur
  JOIN roles r ON r.id = ur.role_id
 WHERE r.name = $1
`, roleName)
	if err != nil {
		return err
	}
	var affected []int
	for rows.Next() {
		var userID int
		if err := rows.Scan(&userID); err != nil {
			rows.Close()
			return err
		}
		affected = append(affected, userID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	result, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE name = $1`, roleName)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return fmt.Errorf(errUnknownRoleFormat, roleName)
	}

	for _, userID := range affected {
		if err := refreshLegacyAdminStateTx(ctx, tx, userID, ""); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func upsertPermissionDefinition(currentName string, def PermissionDefinition) error {
	currentName = normalizeRBACName(currentName)
	def.Name = normalizeRBACName(def.Name)
	def.Description = strings.TrimSpace(def.Description)

	if def.Name == "" {
		return errors.New("permission name required")
	}
	if currentName != "" && isSystemPermission(currentName) {
		return errors.New("system permissions cannot be modified")
	}
	if currentName == "" && isSystemPermission(def.Name) {
		return errors.New("system permissions already exist and cannot be recreated")
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	if currentName == "" {
		_, err := db.ExecContext(ctx, `
INSERT INTO permissions (name, description)
VALUES ($1, NULLIF($2, ''))
`, def.Name, def.Description)
		return err
	}

	result, err := db.ExecContext(ctx, `
UPDATE permissions
   SET name = $2,
       description = NULLIF($3, ''),
       updated_at = now()
 WHERE name = $1
`, currentName, def.Name, def.Description)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return fmt.Errorf(errUnknownPermissionFormat, currentName)
	}
	return nil
}

func deletePermissionDefinition(permissionName string) error {
	permissionName = normalizeRBACName(permissionName)
	if permissionName == "" {
		return errors.New("permission required")
	}
	if isSystemPermission(permissionName) {
		return errors.New("system permissions cannot be deleted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	result, err := db.ExecContext(ctx, `DELETE FROM permissions WHERE name = $1`, permissionName)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return fmt.Errorf(errUnknownPermissionFormat, permissionName)
	}
	return nil
}

func userPermissions(uuid, username string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	userID, err := resolveUserID(ctx, uuid, username)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT p.name
  FROM user_roles ur
  JOIN role_permissions rp ON rp.role_id = ur.role_id
  JOIN permissions p ON p.id = rp.permission_id
 WHERE ur.user_id = $1
 ORDER BY p.name
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		permissions = append(permissions, normalizeRBACName(name))
	}
	return permissions, rows.Err()
}

func userHasPermission(uuid, username, permission string) (bool, bool, error) {
	return userHasAnyPermission(uuid, username, []string{permission})
}

func userHasAnyPermission(uuid, username string, permissions []string) (bool, bool, error) {
	permissions = normalizePermissionList(permissions)
	if len(permissions) == 0 {
		return false, false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	userID, err := resolveUserID(ctx, uuid, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, nil
		}
		return false, false, err
	}

	var (
		matched     bool
		adminAccess bool
	)
	if err := db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM user_roles ur
      JOIN role_permissions rp ON rp.role_id = ur.role_id
      JOIN permissions p ON p.id = rp.permission_id
     WHERE ur.user_id = $1
       AND p.name = ANY($2)
), EXISTS (
    SELECT 1
      FROM user_roles ur
      JOIN role_permissions rp ON rp.role_id = ur.role_id
      JOIN permissions p ON p.id = rp.permission_id
     WHERE ur.user_id = $1
       AND p.name = $3
)
`, userID, pq.Array(permissions), permissionAdminAccess).Scan(&matched, &adminAccess); err != nil {
		return false, false, err
	}
	return matched, adminAccess, nil
}

func userHasRole(uuid, username, roleName string) (bool, error) {
	roleName = normalizeRBACName(roleName)
	if roleName == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	userID, err := resolveUserID(ctx, uuid, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	var exists bool
	err = db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
     WHERE ur.user_id = $1
       AND r.name = $2
)`, userID, roleName).Scan(&exists)
	return exists, err
}

func resolveUserID(ctx context.Context, uuid, username string) (int, error) {
	uuid = strings.TrimSpace(uuid)
	if uuid != "" {
		var id int
		err := db.QueryRowContext(ctx, `
SELECT u.id
  FROM users u
 WHERE u.media_uuid = $1
    OR EXISTS (
        SELECT 1
          FROM identities i
         WHERE i.user_id = u.id
           AND i.media_uuid = $1
    )
 ORDER BY CASE WHEN u.media_uuid = $1 THEN 0 ELSE 1 END, u.id
 LIMIT 1
`, uuid).Scan(&id)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return 0, sql.ErrNoRows
	}

	var id int
	err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&id)
	return id, err
}

func setUserRoleByUsername(username, roleName, source, grantedBy, externalRef string, assign bool) error {
	username = strings.TrimSpace(username)
	roleName = normalizeRBACName(roleName)
	source = normalizeRBACSource(source)
	externalRef = strings.TrimSpace(externalRef)
	if username == "" {
		return errors.New("username required")
	}
	if roleName == "" {
		return errors.New("role required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var (
		userID int
		roleID int
	)
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&userID); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1`, roleName).Scan(&roleID); err != nil {
		return err
	}

	if assign {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO user_roles (user_id, role_id, source, external_ref, granted_by)
VALUES ($1, $2, $3, $4, NULLIF($5, ''))
ON CONFLICT (user_id, role_id, source, external_ref) DO UPDATE
   SET granted_by = NULLIF(EXCLUDED.granted_by, ''),
       updated_at = now()
`, userID, roleID, source, externalRef, strings.TrimSpace(grantedBy)); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
DELETE FROM user_roles
 WHERE user_id = $1
   AND role_id = $2
   AND source = $3
   AND external_ref = $4
`, userID, roleID, source, externalRef); err != nil {
			return err
		}
	}

	if err := refreshLegacyAdminStateTx(ctx, tx, userID, strings.TrimSpace(grantedBy)); err != nil {
		return err
	}

	return tx.Commit()
}

func syncUsersToRole(roleName string, usernames []string, source, externalRef, actor string) (int, int, error) {
	roleName = normalizeRBACName(roleName)
	source = normalizeRBACSource(source)
	externalRef = strings.TrimSpace(externalRef)
	usernames = normalizeDistinctStrings(usernames)
	if roleName == "" {
		return 0, 0, errors.New("role required")
	}
	if source == "" {
		return 0, 0, errors.New("source required")
	}

	if err := ensureUsersExist(usernames); err != nil {
		return 0, 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	var roleID int
	if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1`, roleName).Scan(&roleID); err != nil {
		return 0, 0, err
	}

	existing, err := listSyncedUsersTx(ctx, tx, roleID, source, externalRef)
	if err != nil {
		return 0, 0, err
	}
	target := stringSet(usernames)
	changedUserIDs := make(map[int]struct{})
	added, err := addMissingUsersToRoleTx(ctx, tx, roleID, usernames, source, externalRef, actor, existing, changedUserIDs)
	if err != nil {
		return 0, 0, err
	}
	removed, err := removeExtraUsersFromRoleTx(ctx, tx, roleID, source, externalRef, existing, target, changedUserIDs)
	if err != nil {
		return 0, 0, err
	}
	if err := refreshChangedUsersTx(ctx, tx, changedUserIDs, actor); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return added, removed, nil
}

func validateRoleNames(roles []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	for _, role := range roles {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM roles WHERE name = $1)`, role).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf(errUnknownRoleFormat, role)
		}
	}
	return nil
}

func listManualRolesByUsername(username string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*dbTimeout)
	defer cancel()
	var userID int
	if err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&userID); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
SELECT r.name
  FROM user_roles ur
  JOIN roles r ON r.id = ur.role_id
 WHERE ur.user_id = $1
   AND ur.source = 'manual'
   AND ur.external_ref = ''
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var current []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		current = append(current, normalizeRBACName(role))
	}
	return current, rows.Err()
}

func applyManualRoleChanges(username string, current, target []string, grantedBy string) error {
	currentSet := stringSet(current)
	targetSet := stringSet(target)
	for _, role := range target {
		if _, ok := currentSet[role]; ok {
			continue
		}
		if err := setUserRoleByUsername(username, role, "manual", grantedBy, "", true); err != nil {
			return err
		}
	}
	for _, role := range current {
		if _, ok := targetSet[role]; ok {
			continue
		}
		if err := setUserRoleByUsername(username, role, "manual", grantedBy, "", false); err != nil {
			return err
		}
	}
	return nil
}

func validatePermissionNamesTx(ctx context.Context, tx *sql.Tx, permissions []string) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM permissions WHERE name = ANY($1)`, pq.Array(permissions))
	if err != nil {
		return err
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(permissions))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		found[normalizeRBACName(name)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, permission := range permissions {
		if _, ok := found[permission]; !ok {
			return fmt.Errorf(errUnknownPermissionFormat, permission)
		}
	}
	return nil
}

func upsertRoleRecordTx(ctx context.Context, tx *sql.Tx, currentName string, def RoleDefinition) (int, error) {
	if currentName == "" {
		var roleID int
		err := tx.QueryRowContext(ctx, `
INSERT INTO roles (name, description)
VALUES ($1, NULLIF($2, ''))
RETURNING id
`, def.Name, def.Description).Scan(&roleID)
		return roleID, err
	}
	var roleID int
	if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1`, currentName).Scan(&roleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf(errUnknownRoleFormat, currentName)
		}
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE roles
   SET name = $2,
       description = NULLIF($3, ''),
       updated_at = now()
 WHERE id = $1
`, roleID, def.Name, def.Description); err != nil {
		return 0, err
	}
	return roleID, nil
}

func replaceRolePermissionsTx(ctx context.Context, tx *sql.Tx, roleID int, permissions []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO role_permissions (role_id, permission_id)
SELECT $1, p.id
  FROM permissions p
 WHERE p.name = ANY($2)
`, roleID, pq.Array(permissions))
	return err
}

func ensureUsersExist(usernames []string) error {
	for _, username := range usernames {
		if _, err := upsertUser(User{Username: username}); err != nil {
			return err
		}
	}
	return nil
}

func listSyncedUsersTx(ctx context.Context, tx *sql.Tx, roleID int, source, externalRef string) (map[string]int, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT ur.user_id, u.username
  FROM user_roles ur
  JOIN users u ON u.id = ur.user_id
 WHERE ur.role_id = $1
   AND ur.source = $2
   AND ur.external_ref = $3
`, roleID, source, externalRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	existing := make(map[string]int)
	for rows.Next() {
		var userID int
		var username string
		if err := rows.Scan(&userID, &username); err != nil {
			return nil, err
		}
		existing[strings.TrimSpace(username)] = userID
	}
	return existing, rows.Err()
}

func addMissingUsersToRoleTx(ctx context.Context, tx *sql.Tx, roleID int, usernames []string, source, externalRef, actor string, existing map[string]int, changedUserIDs map[int]struct{}) (int, error) {
	added := 0
	for _, username := range usernames {
		if _, ok := existing[username]; ok {
			continue
		}
		var userID int
		if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&userID); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO user_roles (user_id, role_id, source, external_ref, granted_by)
VALUES ($1, $2, $3, $4, NULLIF($5, ''))
ON CONFLICT (user_id, role_id, source, external_ref) DO UPDATE
   SET granted_by = NULLIF(EXCLUDED.granted_by, ''),
       updated_at = now()
`, userID, roleID, source, externalRef, strings.TrimSpace(actor)); err != nil {
			return 0, err
		}
		changedUserIDs[userID] = struct{}{}
		added++
	}
	return added, nil
}

func removeExtraUsersFromRoleTx(ctx context.Context, tx *sql.Tx, roleID int, source, externalRef string, existing map[string]int, target map[string]struct{}, changedUserIDs map[int]struct{}) (int, error) {
	removed := 0
	for username, userID := range existing {
		if _, ok := target[username]; ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM user_roles
 WHERE user_id = $1
   AND role_id = $2
   AND source = $3
   AND external_ref = $4
`, userID, roleID, source, externalRef); err != nil {
			return 0, err
		}
		changedUserIDs[userID] = struct{}{}
		removed++
	}
	return removed, nil
}

func refreshChangedUsersTx(ctx context.Context, tx *sql.Tx, changedUserIDs map[int]struct{}, actor string) error {
	for userID := range changedUserIDs {
		if err := refreshLegacyAdminStateTx(ctx, tx, userID, actor); err != nil {
			return err
		}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func ensureDefaultUserRoleAssignment(userID int) error {
	if userID <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	_, err := db.ExecContext(ctx, `
INSERT INTO user_roles (user_id, role_id, source, external_ref, granted_by)
SELECT $1, r.id, 'system-default', '', 'system:rbac'
  FROM roles r
 WHERE r.name = $2
ON CONFLICT (user_id, role_id, source, external_ref) DO NOTHING
`, userID, roleUser)
	return err
}

func refreshLegacyAdminStateTx(ctx context.Context, tx *sql.Tx, userID int, grantor string) error {
	var hasAdmin bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
     WHERE ur.user_id = $1
       AND r.name = $2
)`, userID, roleAdmin).Scan(&hasAdmin); err != nil {
		return err
	}

	if hasAdmin {
		_, err := tx.ExecContext(ctx, `
UPDATE users
   SET is_admin = TRUE,
       admin_granted_at = COALESCE(admin_granted_at, now()),
       admin_granted_by = COALESCE(NULLIF($2, ''), admin_granted_by),
       updated_at = now(),
       session_version = session_version + 1
 WHERE id = $1
`, userID, strings.TrimSpace(grantor))
		return err
	}

	_, err := tx.ExecContext(ctx, `
UPDATE users
   SET is_admin = FALSE,
       admin_granted_at = NULL,
       admin_granted_by = NULL,
       updated_at = now(),
       session_version = session_version + 1
 WHERE id = $1
`, userID)
	return err
}
