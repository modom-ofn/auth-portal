package oauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
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
	defaultAuthCodeTTL = 5 * time.Minute
	defaultAccessTTL   = 1 * time.Hour
	defaultRefreshTTL  = 24 * time.Hour
)

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
	if s.AuthCodeTTL <= 0 {
		s.AuthCodeTTL = defaultAuthCodeTTL
	}
	code, err := generateOpaqueToken(32)
	if err != nil {
		return AuthCode{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.AuthCodeTTL)
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
	if s.AccessTokenTTL <= 0 {
		s.AccessTokenTTL = defaultAccessTTL
	}
	tokenID, err := generateOpaqueToken(32)
	if err != nil {
		return AccessToken{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.AccessTokenTTL)
	normalizedScopes := normalizeScopes(scopes)
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO oauth_access_tokens (token_id, client_id, user_id, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`, tokenID, clientID, userID, pq.StringArray(normalizedScopes), expires, now)
	if err != nil {
		return AccessToken{}, err
	}
	return AccessToken{
		TokenID:   tokenID,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    normalizedScopes,
		ExpiresAt: expires,
		CreatedAt: now,
	}, nil
}

func (s Service) CreateRefreshToken(ctx context.Context, accessTokenID string, clientID string, userID int64, scopes []string) (string, time.Time, error) {
	if s.RefreshTokenTTL <= 0 {
		s.RefreshTokenTTL = defaultRefreshTTL
	}
	tokenID, err := generateOpaqueToken(48)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.RefreshTokenTTL)
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO oauth_refresh_tokens (token_id, access_token_id, client_id, user_id, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, tokenID, accessTokenID, clientID, userID, pq.StringArray(normalizeScopes(scopes)), expires, now)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenID, expires, nil
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
	if time.Now().After(token.ExpiresAt) {
		return AccessToken{}, ErrTokenExpired
	}
	token.Scopes = scopes
	return token, nil
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
