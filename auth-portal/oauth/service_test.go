package oauth

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func TestServiceCreateClient(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
RETURNING client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
`

	redirects := pq.StringArray{"https://example.com/callback"}
	scopes := pq.StringArray{"email", "openid", "profile"}
	grantTypes := pq.StringArray{"authorization_code", "refresh_token"}
	responseTypes := pq.StringArray{"code"}

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"My App",
			redirects,
			scopes,
			grantTypes,
			responseTypes,
			sqlmock.AnyArg(),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
		}).AddRow(
			"client-123",
			"db-secret",
			"My App",
			redirects,
			scopes,
			grantTypes,
			responseTypes,
			now,
			now,
		))

	client, secret, err := svc.CreateClient(context.Background(), " My App ", []string{
		"https://example.com/callback",
	}, []string{"profile", "email"})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret == "" {
		t.Fatalf("expected secret to be returned")
	}
	if client.ClientSecret.Valid {
		t.Errorf("expected sanitized client secret to be empty")
	}
	if got := client.Name; got != "My App" {
		t.Errorf("unexpected name: %s", got)
	}
	expectedScopes := []string{"email", "openid", "profile"}
	if len(client.Scopes) != len(expectedScopes) {
		t.Fatalf("unexpected scope count: %d", len(client.Scopes))
	}
	for i, scope := range expectedScopes {
		if client.Scopes[i] != scope {
			t.Errorf("scope[%d] expected %s got %s", i, scope, client.Scopes[i])
		}
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("unexpected redirect URIs: %+v", client.RedirectURIs)
	}
	if len(client.GrantTypes) != 2 {
		t.Errorf("expected two grant types, got %d", len(client.GrantTypes))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServiceUpdateClient(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
UPDATE oauth_clients
   SET name = $2,
       redirect_uris = $3,
       scopes = $4,
       updated_at = $5
 WHERE client_id = $1
RETURNING client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
`

	redirects := pq.StringArray{"https://example.com/app"}
	scopes := pq.StringArray{"email", "openid"}
	grantTypes := pq.StringArray{"authorization_code", "refresh_token"}
	responseTypes := pq.StringArray{"code"}
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(
			"client-123",
			"My App Updated",
			redirects,
			scopes,
			sqlmock.AnyArg(),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
		}).AddRow(
			"client-123",
			"db-secret",
			"My App Updated",
			redirects,
			scopes,
			grantTypes,
			responseTypes,
			now.Add(-time.Hour),
			now,
		))

	client, err := svc.UpdateClient(context.Background(), "client-123", " My App Updated ", []string{
		"https://example.com/app",
	}, []string{"openid", "email"})
	if err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if client.ClientSecret.Valid {
		t.Errorf("expected sanitized client secret to be empty")
	}
	if got := client.Name; got != "My App Updated" {
		t.Errorf("unexpected name: %s", got)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://example.com/app" {
		t.Errorf("unexpected redirect URIs: %+v", client.RedirectURIs)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServiceRotateClientSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
UPDATE oauth_clients
   SET client_secret = $2,
       updated_at = now()
 WHERE client_id = $1
`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs("client-123", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	secret, err := svc.RotateClientSecret(context.Background(), "client-123")
	if err != nil {
		t.Fatalf("RotateClientSecret: %v", err)
	}
	if secret == "" {
		t.Fatalf("expected secret to be returned")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServiceRotateClientSecretNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
UPDATE oauth_clients
   SET client_secret = $2,
       updated_at = now()
 WHERE client_id = $1
`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs("missing", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	if _, err := svc.RotateClientSecret(context.Background(), "missing"); err != ErrClientNotFound {
		t.Fatalf("expected ErrClientNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServiceDeleteClient(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM oauth_clients WHERE client_id = $1`)).
		WithArgs("client-123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := svc.DeleteClient(context.Background(), "client-123"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthenticateClientHashedSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`
	redirects := pq.StringArray{"https://example.com/callback"}
	scopes := pq.StringArray{"openid"}
	grantTypes := pq.StringArray{"authorization_code"}
	responseTypes := pq.StringArray{"code"}
	now := time.Now().UTC()
	hashed, _ := bcrypt.GenerateFromPassword([]byte("super-secret"), bcrypt.DefaultCost)

	row := sqlmock.NewRows([]string{
		"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
	}).AddRow(
		"client-123", string(hashed), "My App", redirects, scopes, grantTypes, responseTypes, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("client-123").WillReturnRows(row)

	client, err := svc.AuthenticateClient(context.Background(), "client-123", "super-secret")
	if err != nil {
		t.Fatalf("AuthenticateClient: %v", err)
	}
	if client.ClientSecret.Valid {
		t.Fatalf("expected sanitized client secret")
	}

	row2 := sqlmock.NewRows([]string{
		"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
	}).AddRow(
		"client-123", string(hashed), "My App", redirects, scopes, grantTypes, responseTypes, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("client-123").WillReturnRows(row2)

	if _, err := svc.AuthenticateClient(context.Background(), "client-123", "wrong"); err != ErrClientAuthFailed {
		t.Fatalf("expected ErrClientAuthFailed, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthenticateClientLegacySecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`
	redirects := pq.StringArray{"https://example.com/callback"}
	scopes := pq.StringArray{"openid"}
	grantTypes := pq.StringArray{"authorization_code"}
	responseTypes := pq.StringArray{"code"}
	now := time.Now().UTC()

	row := sqlmock.NewRows([]string{
		"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
	}).AddRow(
		"client-legacy", "legacy-secret", "Legacy App", redirects, scopes, grantTypes, responseTypes, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("client-legacy").WillReturnRows(row)

	if _, err := svc.AuthenticateClient(context.Background(), "client-legacy", "legacy-secret"); err != nil {
		t.Fatalf("AuthenticateClient legacy: %v", err)
	}

	row2 := sqlmock.NewRows([]string{
		"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
	}).AddRow(
		"client-legacy", "legacy-secret", "Legacy App", redirects, scopes, grantTypes, responseTypes, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("client-legacy").WillReturnRows(row2)

	if _, err := svc.AuthenticateClient(context.Background(), "client-legacy", "bad"); err != ErrClientAuthFailed {
		t.Fatalf("expected ErrClientAuthFailed for legacy mismatch, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAuthenticateClientPublic(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := Service{DB: db}
	query := `
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`
	redirects := pq.StringArray{"https://example.com/callback"}
	scopes := pq.StringArray{"openid"}
	grantTypes := pq.StringArray{"authorization_code"}
	responseTypes := pq.StringArray{"code"}
	now := time.Now().UTC()

	row := sqlmock.NewRows([]string{
		"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
	}).AddRow(
		"public-client", nil, "Public App", redirects, scopes, grantTypes, responseTypes, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("public-client").WillReturnRows(row)

	if _, err := svc.AuthenticateClient(context.Background(), "public-client", ""); err != nil {
		t.Fatalf("AuthenticateClient public: %v", err)
	}

	row2 := sqlmock.NewRows([]string{
		"client_id", "client_secret", "name", "redirect_uris", "scopes", "grant_types", "response_types", "created_at", "updated_at",
	}).AddRow(
		"public-client", nil, "Public App", redirects, scopes, grantTypes, responseTypes, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("public-client").WillReturnRows(row2)

	if _, err := svc.AuthenticateClient(context.Background(), "public-client", "unexpected"); err != ErrClientAuthFailed {
		t.Fatalf("expected ErrClientAuthFailed for unexpected secret, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNormalizeRedirectURIs(t *testing.T) {
	uris, err := normalizeRedirectURIs([]string{
		" https://example.com/callback ",
		"https://example.com/callback",
		"https://example.com/other",
	})
	if err != nil {
		t.Fatalf("normalizeRedirectURIs: %v", err)
	}
	expected := []string{
		"https://example.com/callback",
		"https://example.com/other",
	}
	if len(uris) != len(expected) {
		t.Fatalf("expected %d uris, got %d", len(expected), len(uris))
	}
	for i, uri := range expected {
		if uris[i] != uri {
			t.Errorf("uri[%d] expected %s got %s", i, uri, uris[i])
		}
	}
	if _, err := normalizeRedirectURIs([]string{"invalid://"}); err == nil {
		t.Fatalf("expected error for invalid uri")
	}
}

func TestNormalizeScopes(t *testing.T) {
	scopes := normalizeScopes([]string{"email", "profile", "email"})
	expected := []string{"email", "openid", "profile"}
	if len(scopes) != len(expected) {
		t.Fatalf("expected %d scopes, got %d", len(expected), len(scopes))
	}
	for i, scope := range expected {
		if scopes[i] != scope {
			t.Errorf("scope[%d] expected %s got %s", i, scope, scopes[i])
		}
	}
}
