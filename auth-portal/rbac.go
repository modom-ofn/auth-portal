package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/lib/pq"
)

const (
	roleAdminName = "admin"
	roleUserName  = "user"

	permAdminAll      = "admin:all"
	permAdminAccess   = "admin:access"
	permConfigRead    = "config:read"
	permConfigWrite   = "config:write"
	permUsersRead     = "users:read"
	permUsersManage   = "users:manage"
	permOAuthRead     = "oauth:read"
	permOAuthManage   = "oauth:manage"
	permBackupsRead   = "backups:read"
	permBackupsManage = "backups:manage"
)

var (
	ErrReservedRole        = errors.New("role name is reserved")
	ErrForbiddenPermission = errors.New("permission is reserved for admins")
	ErrRoleNotFound        = errors.New("role not found")
)

type permissionSeed struct {
	Name        string
	Description string
}

type roleSeed struct {
	Name        string
	Description string
	Permissions []string
}

var basePermissionSeeds = []permissionSeed{
	{Name: permAdminAll, Description: "Full administrative override"},
	{Name: permAdminAccess, Description: "Access the admin console"},
	{Name: permConfigRead, Description: "View configuration"},
	{Name: permConfigWrite, Description: "Modify configuration"},
	{Name: permUsersRead, Description: "View users"},
	{Name: permUsersManage, Description: "Create or update users"},
	{Name: permOAuthRead, Description: "View OAuth clients"},
	{Name: permOAuthManage, Description: "Manage OAuth clients"},
	{Name: permBackupsRead, Description: "List and download backups"},
	{Name: permBackupsManage, Description: "Create, restore, or delete backups"},
}

var baseRoleSeeds = []roleSeed{
	{
		Name:        roleAdminName,
		Description: "Full administrative access",
		Permissions: []string{
			permAdminAll,
			permAdminAccess,
			permConfigRead,
			permConfigWrite,
			permUsersRead,
			permUsersManage,
			permOAuthRead,
			permOAuthManage,
			permBackupsRead,
			permBackupsManage,
		},
	},
	{
		Name:        roleUserName,
		Description: "Standard authenticated user",
		Permissions: nil,
	},
}

// ensureRBACSeedData bootstraps roles, permissions, and default assignments.
func ensureRBACSeedData() error {
	if db == nil {
		return errors.New("db not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	permIDs := make(map[string]int64, len(basePermissionSeeds))
	for _, seed := range basePermissionSeeds {
		id, err := upsertPermission(ctx, seed)
		if err != nil {
			return fmt.Errorf("seed permission %q: %w", seed.Name, err)
		}
		permIDs[seed.Name] = id
	}

	roleIDs := make(map[string]int64, len(baseRoleSeeds))
	for _, seed := range baseRoleSeeds {
		id, err := upsertRole(ctx, seed)
		if err != nil {
			return fmt.Errorf("seed role %q: %w", seed.Name, err)
		}
		roleIDs[seed.Name] = id
	}

	for _, seed := range baseRoleSeeds {
		roleID := roleIDs[seed.Name]
		for _, permName := range seed.Permissions {
			permID := permIDs[permName]
			if permID == 0 || roleID == 0 {
				continue
			}
			if err := ensureRolePermission(ctx, roleID, permID); err != nil {
				return fmt.Errorf("link role %q to permission %q: %w", seed.Name, permName, err)
			}
		}
	}

	if adminRoleID := roleIDs[roleAdminName]; adminRoleID != 0 {
		if err := backfillAdminRole(ctx, adminRoleID); err != nil {
			return fmt.Errorf("backfill admin role: %w", err)
		}
	}
	if userRoleID := roleIDs[roleUserName]; userRoleID != 0 {
		if err := backfillUserRole(ctx, userRoleID); err != nil {
			return fmt.Errorf("backfill user role: %w", err)
		}
	}

	return nil
}

func upsertPermission(ctx context.Context, seed permissionSeed) (int64, error) {
	name := strings.ToLower(strings.TrimSpace(seed.Name))
	if name == "" {
		return 0, errors.New("permission name required")
	}
	var id int64
	err := db.QueryRowContext(ctx, `
INSERT INTO permissions (name, description)
VALUES ($1, NULLIF($2, ''))
ON CONFLICT (name) DO UPDATE
   SET description = COALESCE(NULLIF(EXCLUDED.description, ''), permissions.description),
       updated_at  = now()
RETURNING id
`, name, strings.TrimSpace(seed.Description)).Scan(&id)
	return id, err
}

func upsertRole(ctx context.Context, seed roleSeed) (int64, error) {
	name := strings.ToLower(strings.TrimSpace(seed.Name))
	if name == "" {
		return 0, errors.New("role name required")
	}
	var id int64
	err := db.QueryRowContext(ctx, `
INSERT INTO roles (name, description)
VALUES ($1, NULLIF($2, ''))
ON CONFLICT (name) DO UPDATE
   SET description = COALESCE(NULLIF(EXCLUDED.description, ''), roles.description),
       updated_at  = now()
RETURNING id
`, name, strings.TrimSpace(seed.Description)).Scan(&id)
	return id, err
}

func ensureRolePermission(ctx context.Context, roleID, permID int64) error {
	if roleID == 0 || permID == 0 {
		return errors.New("role and permission IDs required")
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT (role_id, permission_id) DO NOTHING
`, roleID, permID)
	return err
}

func backfillAdminRole(ctx context.Context, roleID int64) error {
	_, err := db.ExecContext(ctx, `
WITH inserted AS (
  INSERT INTO user_roles (user_id, role_id, assigned_by)
  SELECT u.id, $1, 'system:admin-backfill'
    FROM users u
   WHERE u.is_admin = TRUE
     AND NOT EXISTS (
       SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = $1
     )
  RETURNING user_id
)
UPDATE users
   SET session_version = session_version + 1
 WHERE id IN (SELECT user_id FROM inserted)
`, roleID)
	return err
}

func backfillUserRole(ctx context.Context, roleID int64) error {
	_, err := db.ExecContext(ctx, `
WITH inserted AS (
  INSERT INTO user_roles (user_id, role_id, assigned_by)
  SELECT u.id, $1, 'system:user-backfill'
    FROM users u
   WHERE NOT EXISTS (
     SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = $1
   )
  RETURNING user_id
)
UPDATE users
   SET session_version = session_version + 1
 WHERE id IN (SELECT user_id FROM inserted)
`, roleID)
	return err
}

type RoleDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

type RoleInfo struct {
	RoleDefinition
	UserCount int  `json:"userCount"`
	BuiltIn   bool `json:"builtIn"`
}

func createCustomRole(name, description string, permissions []string, createdBy string) (RoleDefinition, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return RoleDefinition{}, errors.New("role name required")
	}
	if isBuiltInRole(name) {
		return RoleDefinition{}, ErrReservedRole
	}
	perms := normalizePermissions(permissions)
	if len(perms) == 0 {
		return RoleDefinition{}, errors.New("at least one permission is required")
	}
	for _, p := range perms {
		if p == permAdminAll || p == permAdminAccess {
			return RoleDefinition{}, ErrForbiddenPermission
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return RoleDefinition{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var roleID int64
	err = tx.QueryRowContext(ctx, `
INSERT INTO roles (name, description)
VALUES ($1, NULLIF($2, ''))
ON CONFLICT (name) DO NOTHING
RETURNING id
`, name, strings.TrimSpace(description)).Scan(&roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RoleDefinition{}, fmt.Errorf("role %q already exists", name)
		}
		return RoleDefinition{}, err
	}
	if roleID == 0 {
		return RoleDefinition{}, fmt.Errorf("role %q already exists", name)
	}

	for _, permName := range perms {
		var permID int64
		if err := tx.QueryRowContext(ctx, `
INSERT INTO permissions (name)
VALUES ($1)
ON CONFLICT (name) DO UPDATE
   SET updated_at = now()
RETURNING id
`, permName).Scan(&permID); err != nil {
			return RoleDefinition{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT (role_id, permission_id) DO NOTHING
`, roleID, permID); err != nil {
			return RoleDefinition{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return RoleDefinition{}, err
	}

	return RoleDefinition{
		Name:        name,
		Description: strings.TrimSpace(description),
		Permissions: perms,
	}, nil
}

func isBuiltInRole(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case roleAdminName, roleUserName:
		return true
	default:
		return false
	}
}

// updateRole rewrites description/permissions for a non-built-in role and bumps sessions for affected users.
func updateRole(name, description string, permissions []string) (RoleDefinition, []int, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return RoleDefinition{}, nil, errors.New("role name required")
	}
	if isBuiltInRole(name) {
		return RoleDefinition{}, nil, ErrReservedRole
	}
	perms := normalizePermissions(permissions)
	if len(perms) == 0 {
		return RoleDefinition{}, nil, errors.New("at least one permission is required")
	}
	for _, p := range perms {
		if p == permAdminAll || p == permAdminAccess {
			return RoleDefinition{}, nil, ErrForbiddenPermission
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return RoleDefinition{}, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var roleID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1`, name).Scan(&roleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RoleDefinition{}, nil, ErrRoleNotFound
		}
		return RoleDefinition{}, nil, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE roles SET description = NULLIF($1,'') WHERE id = $2`, strings.TrimSpace(description), roleID); err != nil {
		return RoleDefinition{}, nil, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return RoleDefinition{}, nil, err
	}

	for _, permName := range perms {
		var permID int64
		if err := tx.QueryRowContext(ctx, `
INSERT INTO permissions (name)
VALUES ($1)
ON CONFLICT (name) DO UPDATE
   SET updated_at = now()
RETURNING id
`, permName).Scan(&permID); err != nil {
			return RoleDefinition{}, nil, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT (role_id, permission_id) DO NOTHING
`, roleID, permID); err != nil {
			return RoleDefinition{}, nil, err
		}
	}

	userIDs := make([]int, 0)
	rows, err := tx.QueryContext(ctx, `SELECT user_id FROM user_roles WHERE role_id = $1`, roleID)
	if err != nil {
		return RoleDefinition{}, nil, err
	}
	for rows.Next() {
		var uid int
		if scanErr := rows.Scan(&uid); scanErr != nil {
			rows.Close()
			return RoleDefinition{}, nil, scanErr
		}
		userIDs = append(userIDs, uid)
	}
	if err := rows.Close(); err != nil {
		return RoleDefinition{}, nil, err
	}
	if len(userIDs) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET session_version = session_version + 1 WHERE id = ANY($1)`, pq.Array(userIDs)); err != nil {
			return RoleDefinition{}, nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return RoleDefinition{}, nil, err
	}

	return RoleDefinition{
		Name:        name,
		Description: strings.TrimSpace(description),
		Permissions: perms,
	}, userIDs, nil
}

func listRoles(ctx context.Context) ([]RoleInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT r.name, r.description,
       COALESCE(array_agg(p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), '{}') AS permissions,
       COUNT(DISTINCT ur.user_id) AS user_count
  FROM roles r
  LEFT JOIN role_permissions rp ON rp.role_id = r.id
  LEFT JOIN permissions p ON p.id = rp.permission_id
  LEFT JOIN user_roles ur ON ur.role_id = r.id
 GROUP BY r.id, r.name, r.description
 ORDER BY lower(r.name)
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []RoleInfo
	for rows.Next() {
		var (
			name      string
			desc      sql.NullString
			perms     []string
			userCount int
		)
		if err := rows.Scan(&name, &desc, pq.Array(&perms), &userCount); err != nil {
			return nil, err
		}
		roles = append(roles, RoleInfo{
			RoleDefinition: RoleDefinition{
				Name:        strings.TrimSpace(name),
				Description: strings.TrimSpace(desc.String),
				Permissions: normalizePermissions(perms),
			},
			UserCount: userCount,
			BuiltIn:   isBuiltInRole(name),
		})
	}
	return roles, rows.Err()
}

func roleIDByName(ctx context.Context, name string) (int64, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return 0, errors.New("role name required")
	}
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	var id int64
	err := db.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1`, name).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrRoleNotFound
		}
		return 0, err
	}
	return id, nil
}

func deleteRoleByName(name string) ([]int, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil, errors.New("role name required")
	}
	if isBuiltInRole(name) {
		return nil, ErrReservedRole
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var roleID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1`, name).Scan(&roleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}

	userIDs := make([]int, 0)
	rows, err := tx.QueryContext(ctx, `SELECT user_id FROM user_roles WHERE role_id = $1`, roleID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var uid int
		if scanErr := rows.Scan(&uid); scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		userIDs = append(userIDs, uid)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE role_id = $1`, roleID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, roleID); err != nil {
		return nil, err
	}
	if len(userIDs) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET session_version = session_version + 1 WHERE id = ANY($1)`, pq.Array(userIDs)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return userIDs, nil
}

func userHasAnyPermission(uuid, username string, perms []string) (bool, bool, error) {
	normalized := normalizePermissions(perms)
	if len(normalized) == 0 {
		return true, false, nil
	}

	user, err := lookupUserForAuthz(uuid, username)
	if err != nil {
		return false, false, err
	}

	permSet, err := userPermissionSet(user.ID)
	if err != nil {
		return false, false, err
	}

	adminLike := user.IsAdmin || permSet[permAdminAll]
	if adminLike {
		return true, true, nil
	}

	for _, p := range normalized {
		if permSet[p] {
			return true, adminLike, nil
		}
	}
	return false, adminLike, nil
}

func lookupUserForAuthz(uuid, username string) (User, error) {
	uuid = strings.TrimSpace(uuid)
	if uuid != "" {
		if u, err := getUserByUUIDPreferred(uuid); err == nil {
			return u, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return User{}, err
		}
	}

	username = strings.TrimSpace(username)
	if username != "" {
		return userByUsername(username)
	}

	return User{}, sql.ErrNoRows
}

func userPermissionSet(userID int) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT p.name
  FROM permissions p
  JOIN role_permissions rp ON rp.permission_id = p.id
  JOIN user_roles ur ON ur.role_id = rp.role_id
 WHERE ur.user_id = $1
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	perms := make(map[string]bool)
	for rows.Next() {
		var name string
		if scanErr := rows.Scan(&name); scanErr != nil {
			return nil, scanErr
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			perms[name] = true
		}
	}
	return perms, rows.Err()
}

func normalizePermissions(perms []string) []string {
	seen := make(map[string]struct{}, len(perms))
	var out []string
	for _, p := range perms {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func ensureUserRoleByUsername(username, roleName, grantedBy string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username required")
	}
	roleName = strings.ToLower(strings.TrimSpace(roleName))
	if roleName == "" {
		return errors.New("role name required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	var userID int
	err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&userID)
	if err != nil {
		return err
	}

	return ensureUserRoleByID(ctx, userID, roleName, grantedBy)
}

func ensureUserRoleByID(ctx context.Context, userID int, roleName, grantedBy string) error {
	if userID == 0 {
		return errors.New("user ID required")
	}
	roleName = strings.ToLower(strings.TrimSpace(roleName))
	if roleName == "" {
		return errors.New("role name required")
	}

	res, err := db.ExecContext(ctx, `
WITH role_match AS (
  SELECT id FROM roles WHERE name = $2
),
inserted AS (
  INSERT INTO user_roles (user_id, role_id, assigned_by)
  SELECT $1, rm.id, NULLIF($3, '')
    FROM role_match rm
  ON CONFLICT (user_id, role_id) DO NOTHING
  RETURNING user_id
)
UPDATE users
   SET session_version = session_version + 1
 WHERE id IN (SELECT user_id FROM inserted)
`, userID, roleName, strings.TrimSpace(grantedBy))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		exists, _ := roleIDByName(ctx, roleName)
		if exists == 0 {
			return ErrRoleNotFound
		}
	}
	return nil
}

func removeUserRoleByID(ctx context.Context, userID int, roleName string) error {
	roleName = strings.ToLower(strings.TrimSpace(roleName))
	if userID == 0 || roleName == "" {
		return errors.New("user ID and role name required")
	}

	res, err := db.ExecContext(ctx, `
WITH removed AS (
  DELETE FROM user_roles ur
   USING roles r
   WHERE ur.user_id = $1
     AND ur.role_id = r.id
     AND r.name = $2
  RETURNING ur.user_id
)
UPDATE users
   SET session_version = session_version + 1
 WHERE id IN (SELECT user_id FROM removed)
`, userID, roleName)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		exists, _ := roleIDByName(ctx, roleName)
		if exists == 0 {
			return ErrRoleNotFound
		}
	}
	return nil
}

func logPermissionDecision(username, uuid string, allowed bool, perms []string, err error) {
	if err != nil {
		log.Printf("authz check failed for %s (%s) perms=%v err=%v", username, uuid, perms, err)
		return
	}
	if !allowed {
		log.Printf("authz denied for %s (%s) perms=%v", username, uuid, perms)
	}
}

func adminFlagFromUser(u User) (bool, error) {
	if u.IsAdmin {
		return true, nil
	}
	perms, err := userPermissionSet(u.ID)
	if err != nil {
		return false, err
	}
	return perms[permAdminAll], nil
}
