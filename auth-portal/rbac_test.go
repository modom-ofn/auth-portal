package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
)

func TestUserHasAnyPermission(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	previousDB := db
	db = mockDB
	defer func() { db = previousDB }()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM users WHERE username = $1`)).
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectQuery(regexp.QuoteMeta(`
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
)`)).
		WithArgs(42, sqlmock.AnyArg(), permissionAdminAccess).
		WillReturnRows(sqlmock.NewRows([]string{"matched", "admin_access"}).AddRow(true, false))

	matched, adminAccess, err := userHasAnyPermission("", "alice", []string{permissionConfigRead})
	if err != nil {
		t.Fatalf("userHasAnyPermission: %v", err)
	}
	if !matched {
		t.Fatal("expected permission to match")
	}
	if adminAccess {
		t.Fatal("expected admin access to be false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRequirePermissionAllowsMatchingPermission(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	previousDB := db
	db = mockDB
	defer func() { db = previousDB }()

	previousSecret := sessionSecret
	sessionSecret = []byte("01234567890123456789012345678901")
	defer func() { sessionSecret = previousSecret }()

	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{
		Username: "alice",
		Version:  7,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	signed, err := token.SignedString(sessionSecret)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, username, email, media_uuid, media_token, media_access,
		       is_admin, admin_granted_at, admin_granted_by, session_version
		FROM users
		WHERE username = $1
	`)).
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "email", "media_uuid", "media_token", "media_access",
			"is_admin", "admin_granted_at", "admin_granted_by", "session_version",
		}).AddRow(42, "alice", nil, nil, nil, true, false, nil, nil, int64(7)))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM users WHERE username = $1`)).
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectQuery(regexp.QuoteMeta(`
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
)`)).
		WithArgs(42, sqlmock.AnyArg(), permissionAdminAccess).
		WillReturnRows(sqlmock.NewRows([]string{"matched", "admin_access"}).AddRow(true, true))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM users WHERE username = $1`)).
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectQuery(regexp.QuoteMeta(`
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
)`)).
		WithArgs(42, sqlmock.AnyArg(), permissionAdminAccess).
		WillReturnRows(sqlmock.NewRows([]string{"matched", "admin_access"}).AddRow(true, true))

	called := false
	handler := requirePermission(permissionConfigRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = adminFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: signed})
	req = req.WithContext(withUUID(withUsername(req.Context(), "alice"), ""))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
	if !called {
		t.Fatal("expected admin flag in context")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNormalizeLDAPGroupRoleMappings(t *testing.T) {
	values := []LDAPGroupRoleMapping{
		{LDAPGroup: " ops-admins ", Role: " ADMIN "},
		{LDAPGroup: "ops-admins", Role: "admin"},
		{LDAPGroup: "viewers", Role: "viewer"},
		{LDAPGroup: "", Role: "user"},
	}
	got := normalizeLDAPGroupRoleMappings(values)
	if len(got) != 2 {
		t.Fatalf("expected 2 mappings, got %+v", got)
	}
	if got[0].Role != "admin" || got[1].Role != "viewer" {
		t.Fatalf("unexpected normalized mappings: %+v", got)
	}
}

func TestValidateLDAPSyncConfigRequiresGroupFieldsWhenEnabled(t *testing.T) {
	cfg := defaultLDAPSyncConfig()
	cfg.GroupSyncEnabled = true
	cfg.GroupSearchBaseDN = ""
	cfg.GroupRoleMappings = []LDAPGroupRoleMapping{{LDAPGroup: "admins", Role: "admin"}}

	if err := validateLDAPSyncConfig(cfg); err == nil {
		t.Fatal("expected validation error when group search base DN is missing")
	}
}
