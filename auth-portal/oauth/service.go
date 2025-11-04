package oauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

var (
	ErrClientNotFound  = errors.New("oauth: client not found")
	ErrAuthCodeInvalid = errors.New("oauth: authorization code invalid")
	ErrTokenNotFound   = errors.New("oauth: token not found")
	ErrTokenExpired    = errors.New("oauth: token expired")
	ErrTokenRevoked    = errors.New("oauth: token revoked")
)

const (
	defaultAuthCodeTTL = 5 * time.Minute
	defaultAccessTTL   = 1 * time.Hour
	defaultRefreshTTL  = 24 * time.Hour
)

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type Service struct {
	DB              *sql.DB
	AuthCodeTTL     time.Duration
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

type Client struct {
	ClientID      string
	ClientSecret  sql.NullString
	Name          string
	RedirectURIs  []string
	Scopes        []string
	GrantTypes    []string
	ResponseTypes []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type AuthCode struct {
	Code          string
	ClientID      string
	UserID        int64
	Scopes        []string
	RedirectURI   string
	ExpiresAt     time.Time
	CodeChallenge sql.NullString
	CodeMethod    sql.NullString
	CreatedAt     time.Time
}

type AccessToken struct {
	TokenID   string
	ClientID  string
	UserID    int64
	Scopes    []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (s Service) GetClient(ctx context.Context, id string) (Client, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Client{}, ErrClientNotFound
	}
	var (
		client        Client
		redirectURIs  pq.StringArray
		scopes        pq.StringArray
		grantTypes    pq.StringArray
		responseTypes pq.StringArray
	)
	err := s.DB.QueryRowContext(ctx, `
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 WHERE client_id = $1
 LIMIT 1
`, id).Scan(
		&client.ClientID,
		&client.ClientSecret,
		&client.Name,
		&redirectURIs,
		&scopes,
		&grantTypes,
		&responseTypes,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Client{}, ErrClientNotFound
		}
		return Client{}, err
	}
	client.RedirectURIs = redirectURIs
	client.Scopes = scopes
	client.GrantTypes = grantTypes
	client.ResponseTypes = responseTypes
	return client, nil
}

func (s Service) CreateAuthCode(ctx context.Context, clientID string, userID int64, redirectURI string, scopes []string, codeChallenge, codeMethod string) (AuthCode, error) {
	code, err := generateOpaqueToken(32)
	if err != nil {
		return AuthCode{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.authCodeTTL())
	normalizedScopes := normalizeScopes(scopes)
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO oauth_auth_codes (code, client_id, user_id, scopes, redirect_uri, expires_at, code_challenge, code_method, created_at)
VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9)
`, code, clientID, userID, pq.StringArray(normalizedScopes), redirectURI, expires, strings.TrimSpace(codeChallenge), strings.TrimSpace(codeMethod), now)
	if err != nil {
		return AuthCode{}, err
	}
	return AuthCode{
		Code:          code,
		ClientID:      clientID,
		UserID:        userID,
		Scopes:        normalizedScopes,
		RedirectURI:   redirectURI,
		ExpiresAt:     expires,
		CodeChallenge: sql.NullString{String: strings.TrimSpace(codeChallenge), Valid: strings.TrimSpace(codeChallenge) != ""},
		CodeMethod:    sql.NullString{String: strings.TrimSpace(codeMethod), Valid: strings.TrimSpace(codeMethod) != ""},
		CreatedAt:     now,
	}, nil
}

func (s Service) ConsumeAuthCode(ctx context.Context, code string) (AuthCode, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return AuthCode{}, ErrAuthCodeInvalid
	}
	var (
		authCode      AuthCode
		scopes        pq.StringArray
		codeChallenge sql.NullString
		codeMethod    sql.NullString
	)
	err := s.DB.QueryRowContext(ctx, `
UPDATE oauth_auth_codes
   SET consumed_at = now()
 WHERE code = $1
   AND consumed_at IS NULL
   AND expires_at > now()
RETURNING code, client_id, user_id, scopes, redirect_uri, expires_at, code_challenge, code_method, created_at
`, code).Scan(
		&authCode.Code,
		&authCode.ClientID,
		&authCode.UserID,
		&scopes,
		&authCode.RedirectURI,
		&authCode.ExpiresAt,
		&codeChallenge,
		&codeMethod,
		&authCode.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthCode{}, ErrAuthCodeInvalid
		}
		return AuthCode{}, err
	}
	authCode.Scopes = scopes
	authCode.CodeChallenge = codeChallenge
	authCode.CodeMethod = codeMethod
	return authCode, nil
}

func (s Service) CreateAccessToken(ctx context.Context, clientID string, userID int64, scopes []string) (AccessToken, error) {
	return s.insertAccessToken(ctx, s.DB, clientID, userID, scopes)
}

func (s Service) CreateRefreshToken(ctx context.Context, accessTokenID string, clientID string, userID int64, scopes []string) (string, time.Time, error) {
	return s.insertRefreshToken(ctx, s.DB, accessTokenID, clientID, userID, scopes)
}

func (s Service) UseRefreshToken(ctx context.Context, tokenID string) (AccessToken, string, time.Time, error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return AccessToken{}, "", time.Time{}, ErrTokenNotFound
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return AccessToken{}, "", time.Time{}, err
	}
	defer tx.Rollback()

	var (
		refreshTokenID string
		accessTokenID  string
		clientID       string
		userID         int64
		scopes         pq.StringArray
		expiresAt      time.Time
		revokedAt      sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
SELECT token_id, access_token_id, client_id, user_id, scopes, expires_at, revoked_at
  FROM oauth_refresh_tokens
 WHERE token_id = $1
 FOR UPDATE
`, tokenID).Scan(
		&refreshTokenID,
		&accessTokenID,
		&clientID,
		&userID,
		&scopes,
		&expiresAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccessToken{}, "", time.Time{}, ErrTokenNotFound
		}
		return AccessToken{}, "", time.Time{}, err
	}

	now := time.Now().UTC()
	if revokedAt.Valid {
		return AccessToken{}, "", time.Time{}, ErrTokenRevoked
	}
	if now.After(expiresAt) {
		_, _ = tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE token_id = $1`, tokenID)
		return AccessToken{}, "", time.Time{}, ErrTokenExpired
	}

	// Revoke previous tokens
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE token_id = $1`, tokenID); err != nil {
		return AccessToken{}, "", time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_access_tokens SET revoked_at = now() WHERE token_id = $1`, accessTokenID); err != nil {
		return AccessToken{}, "", time.Time{}, err
	}

	newAccess, err := s.insertAccessToken(ctx, tx, clientID, userID, scopes)
	if err != nil {
		return AccessToken{}, "", time.Time{}, err
	}
	newRefresh, refreshExpires, err := s.insertRefreshToken(ctx, tx, newAccess.TokenID, clientID, userID, scopes)
	if err != nil {
		return AccessToken{}, "", time.Time{}, err
	}

	if err := tx.Commit(); err != nil {
		return AccessToken{}, "", time.Time{}, err
	}

	return newAccess, newRefresh, refreshExpires, nil
}

func (s Service) GetAccessToken(ctx context.Context, tokenID string) (AccessToken, error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return AccessToken{}, ErrTokenNotFound
	}
	var (
		token   AccessToken
		scopes  pq.StringArray
		revoked sql.NullTime
	)
	err := s.DB.QueryRowContext(ctx, `
SELECT token_id, client_id, user_id, scopes, expires_at, revoked_at, created_at
  FROM oauth_access_tokens
 WHERE token_id = $1
 LIMIT 1
`, tokenID).Scan(
		&token.TokenID,
		&token.ClientID,
		&token.UserID,
		&scopes,
		&token.ExpiresAt,
		&revoked,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccessToken{}, ErrTokenNotFound
		}
		return AccessToken{}, err
	}
	if revoked.Valid {
		return AccessToken{}, ErrTokenRevoked
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return AccessToken{}, ErrTokenExpired
	}
	token.Scopes = scopes
	return token, nil
}

func (s Service) RecordConsent(ctx context.Context, userID int64, clientID string, scopes []string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return errors.New("oauth: client id required")
	}
	normalized := normalizeScopes(scopes)
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO oauth_consents (user_id, client_id, scopes, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())
ON CONFLICT (user_id, client_id) DO UPDATE
   SET scopes = EXCLUDED.scopes,
       updated_at = now()
`, userID, clientID, pq.StringArray(normalized))
	return err
}

func (s Service) HasConsent(ctx context.Context, userID int64, clientID string, scopes []string) (bool, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return false, errors.New("oauth: client id required")
	}
	var existing pq.StringArray
	err := s.DB.QueryRowContext(ctx, `
SELECT scopes
  FROM oauth_consents
 WHERE user_id = $1
   AND client_id = $2
 LIMIT 1
`, userID, clientID).Scan(&existing)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if len(scopes) == 0 {
		return true, nil
	}
	set := make(map[string]struct{}, len(existing))
	for _, scope := range existing {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := set[scope]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (s Service) authCodeTTL() time.Duration {
	if s.AuthCodeTTL <= 0 {
		return defaultAuthCodeTTL
	}
	return s.AuthCodeTTL
}

func (s Service) accessTokenTTL() time.Duration {
	if s.AccessTokenTTL <= 0 {
		return defaultAccessTTL
	}
	return s.AccessTokenTTL
}

func (s Service) refreshTokenTTL() time.Duration {
	if s.RefreshTokenTTL <= 0 {
		return defaultRefreshTTL
	}
	return s.RefreshTokenTTL
}

func (s Service) insertAccessToken(ctx context.Context, exec sqlExecutor, clientID string, userID int64, scopes []string) (AccessToken, error) {
	tokenID, err := generateOpaqueToken(32)
	if err != nil {
		return AccessToken{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.accessTokenTTL())
	normalized := normalizeScopes(scopes)
	if _, err := exec.ExecContext(ctx, `
INSERT INTO oauth_access_tokens (token_id, client_id, user_id, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`, tokenID, clientID, userID, pq.StringArray(normalized), expires, now); err != nil {
		return AccessToken{}, err
	}
	return AccessToken{
		TokenID:   tokenID,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    normalized,
		ExpiresAt: expires,
		CreatedAt: now,
	}, nil
}

func (s Service) insertRefreshToken(ctx context.Context, exec sqlExecutor, accessTokenID string, clientID string, userID int64, scopes []string) (string, time.Time, error) {
	tokenID, err := generateOpaqueToken(48)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.refreshTokenTTL())
	if _, err := exec.ExecContext(ctx, `
INSERT INTO oauth_refresh_tokens (token_id, access_token_id, client_id, user_id, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, tokenID, accessTokenID, clientID, userID, pq.StringArray(normalizeScopes(scopes)), expires, now); err != nil {
		return "", time.Time{}, err
	}
	return tokenID, expires, nil
}

func normalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{}
	}
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for scope := range set {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func generateOpaqueToken(size int) (string, error) {
	if size <= 0 {
		size = 32
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
