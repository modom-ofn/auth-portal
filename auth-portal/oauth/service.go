package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrClientNotFound   = errors.New("oauth: client not found")
	ErrAuthCodeInvalid  = errors.New("oauth: authorization code invalid")
	ErrTokenNotFound    = errors.New("oauth: token not found")
	ErrTokenExpired     = errors.New("oauth: token expired")
	ErrTokenRevoked     = errors.New("oauth: token revoked")
	ErrConsentRequired  = errors.New("oauth: consent required")
	ErrClientAuthFailed = errors.New("oauth: client authentication failed")
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
	Nonce         sql.NullString
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
	client, _, err := s.getClientRow(ctx, id)
	return client, err
}

func (s Service) AuthenticateClient(ctx context.Context, id, providedSecret string) (Client, error) {
	client, storedSecret, err := s.getClientRow(ctx, id)
	if err != nil {
		return Client{}, err
	}
	if err := verifyClientSecret(storedSecret, providedSecret); err != nil {
		return Client{}, ErrClientAuthFailed
	}
	return client, nil
}

func (s Service) getClientRow(ctx context.Context, id string) (Client, string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Client{}, "", ErrClientNotFound
	}
	var (
		client        Client
		secret        sql.NullString
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
		&secret,
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
			return Client{}, "", ErrClientNotFound
		}
		return Client{}, "", err
	}
	client.RedirectURIs = redirectURIs
	client.Scopes = scopes
	client.GrantTypes = grantTypes
	client.ResponseTypes = responseTypes
	return sanitizeClient(client), strings.TrimSpace(secret.String), nil
}

func (s Service) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
  FROM oauth_clients
 ORDER BY created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var (
			client        Client
			redirectURIs  pq.StringArray
			scopes        pq.StringArray
			grantTypes    pq.StringArray
			responseTypes pq.StringArray
		)
		if err := rows.Scan(
			&client.ClientID,
			&client.ClientSecret,
			&client.Name,
			&redirectURIs,
			&scopes,
			&grantTypes,
			&responseTypes,
			&client.CreatedAt,
			&client.UpdatedAt,
		); err != nil {
			return nil, err
		}
		client.RedirectURIs = redirectURIs
		client.Scopes = scopes
		client.GrantTypes = grantTypes
		client.ResponseTypes = responseTypes
		clients = append(clients, sanitizeClient(client))
	}
	return clients, rows.Err()
}

func (s Service) CreateClient(ctx context.Context, name string, redirectURIs, scopes []string) (Client, string, error) {
	redirects, err := normalizeRedirectURIs(redirectURIs)
	if err != nil {
		return Client{}, "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Client{}, "", errors.New("oauth: name is required")
	}
	normScopes := normalizeScopes(scopes)
	clientID, err := generateOpaqueToken(24)
	if err != nil {
		return Client{}, "", err
	}
	secret, err := generateOpaqueToken(48)
	if err != nil {
		return Client{}, "", err
	}
	hashedSecret, err := hashClientSecret(secret)
	if err != nil {
		return Client{}, "", err
	}
	grantTypes := []string{"authorization_code", "refresh_token"}
	responseTypes := []string{"code"}
	now := time.Now().UTC()

	var (
		client      Client
		redirectArr pq.StringArray
		scopesArr   pq.StringArray
		grantArr    pq.StringArray
		responseArr pq.StringArray
	)
	if err := s.DB.QueryRowContext(ctx, `
INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
RETURNING client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
`, clientID, hashedSecret, name, pq.StringArray(redirects), pq.StringArray(normScopes), pq.StringArray(grantTypes), pq.StringArray(responseTypes), now).Scan(
		&client.ClientID,
		&client.ClientSecret,
		&client.Name,
		&redirectArr,
		&scopesArr,
		&grantArr,
		&responseArr,
		&client.CreatedAt,
		&client.UpdatedAt,
	); err != nil {
		return Client{}, "", err
	}
	client.RedirectURIs = redirectArr
	client.Scopes = scopesArr
	client.GrantTypes = grantArr
	client.ResponseTypes = responseArr

	return sanitizeClient(client), secret, nil
}

func (s Service) UpdateClient(ctx context.Context, clientID string, name string, redirectURIs, scopes []string) (Client, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return Client{}, ErrClientNotFound
	}
	redirects, err := normalizeRedirectURIs(redirectURIs)
	if err != nil {
		return Client{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Client{}, errors.New("oauth: name is required")
	}
	normScopes := normalizeScopes(scopes)
	now := time.Now().UTC()

	var (
		client      Client
		redirectArr pq.StringArray
		scopesArr   pq.StringArray
		grantArr    pq.StringArray
		responseArr pq.StringArray
	)
	err = s.DB.QueryRowContext(ctx, `
UPDATE oauth_clients
   SET name = $2,
       redirect_uris = $3,
       scopes = $4,
       updated_at = $5
 WHERE client_id = $1
RETURNING client_id, client_secret, name, redirect_uris, scopes, grant_types, response_types, created_at, updated_at
`, clientID, name, pq.StringArray(redirects), pq.StringArray(normScopes), now).Scan(
		&client.ClientID,
		&client.ClientSecret,
		&client.Name,
		&redirectArr,
		&scopesArr,
		&grantArr,
		&responseArr,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Client{}, ErrClientNotFound
		}
		return Client{}, err
	}
	client.RedirectURIs = redirectArr
	client.Scopes = scopesArr
	client.GrantTypes = grantArr
	client.ResponseTypes = responseArr
	return sanitizeClient(client), nil
}

func (s Service) RotateClientSecret(ctx context.Context, clientID string) (string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", ErrClientNotFound
	}
	secret, err := generateOpaqueToken(48)
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(secret)
	if err != nil {
		return "", err
	}
	res, err := s.DB.ExecContext(ctx, `
UPDATE oauth_clients
   SET client_secret = $2,
       updated_at = now()
 WHERE client_id = $1
`, clientID, hashed)
	if err != nil {
		return "", err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if rows == 0 {
		return "", ErrClientNotFound
	}
	return secret, nil
}

func (s Service) DeleteClient(ctx context.Context, clientID string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return ErrClientNotFound
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_clients WHERE client_id = $1`, clientID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrClientNotFound
	}
	return nil
}

func hashClientSecret(secret string) (string, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", errors.New("oauth: empty client secret")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func verifyClientSecret(stored, provided string) error {
	stored = strings.TrimSpace(stored)
	provided = strings.TrimSpace(provided)
	if stored == "" && provided == "" {
		return nil
	}
	if stored == "" && provided != "" {
		return errors.New("oauth: client is public, secret not expected")
	}
	if stored != "" && provided == "" {
		return errors.New("oauth: client secret required")
	}
	if strings.HasPrefix(stored, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided))
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1 {
		return nil
	}
	return errors.New("oauth: client secret mismatch")
}

func sanitizeClient(c Client) Client {
	c.ClientSecret = sql.NullString{}
	return c
}

func hashTokenIdentifier(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("oauth: empty token")
	}
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (s Service) CreateAuthCode(ctx context.Context, clientID string, userID int64, redirectURI string, scopes []string, codeChallenge, codeMethod, nonce string) (AuthCode, error) {
	code, err := generateOpaqueToken(32)
	if err != nil {
		return AuthCode{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.authCodeTTL())
	normalizedScopes := normalizeScopes(scopes)
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO oauth_auth_codes (code, client_id, user_id, scopes, redirect_uri, expires_at, code_challenge, code_method, nonce, created_at)
VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10)
`, code, clientID, userID, pq.StringArray(normalizedScopes), redirectURI, expires, strings.TrimSpace(codeChallenge), strings.TrimSpace(codeMethod), strings.TrimSpace(nonce), now)
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
		Nonce:         sql.NullString{String: strings.TrimSpace(nonce), Valid: strings.TrimSpace(nonce) != ""},
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
RETURNING code, client_id, user_id, scopes, redirect_uri, expires_at, code_challenge, code_method, nonce, created_at
`, code).Scan(
		&authCode.Code,
		&authCode.ClientID,
		&authCode.UserID,
		&scopes,
		&authCode.RedirectURI,
		&authCode.ExpiresAt,
		&codeChallenge,
		&codeMethod,
		&authCode.Nonce,
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

func (s Service) UseRefreshToken(ctx context.Context, tokenID, expectedClientID string) (AccessToken, string, time.Time, error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return AccessToken{}, "", time.Time{}, ErrTokenNotFound
	}
	expectedClientID = strings.TrimSpace(expectedClientID)
	if expectedClientID == "" {
		return AccessToken{}, "", time.Time{}, errors.New("oauth: client id required")
	}
	digest, err := hashTokenIdentifier(tokenID)
	if err != nil {
		return AccessToken{}, "", time.Time{}, err
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
`, digest).Scan(
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
	if clientID != expectedClientID {
		return AccessToken{}, "", time.Time{}, ErrTokenNotFound
	}

	now := time.Now().UTC()
	if revokedAt.Valid {
		return AccessToken{}, "", time.Time{}, ErrTokenRevoked
	}
	if now.After(expiresAt) {
		_, _ = tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE token_id = $1`, digest)
		return AccessToken{}, "", time.Time{}, ErrTokenExpired
	}

	// Revoke previous tokens
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE token_id = $1`, digest); err != nil {
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
	digest, err := hashTokenIdentifier(tokenID)
	if err != nil {
		return AccessToken{}, err
	}
	var (
		token   AccessToken
		scopes  pq.StringArray
		revoked sql.NullTime
	)
	err = s.DB.QueryRowContext(ctx, `
SELECT token_id, client_id, user_id, scopes, expires_at, revoked_at, created_at
  FROM oauth_access_tokens
 WHERE token_id = $1
 LIMIT 1
`, digest).Scan(
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
	token.TokenID = tokenID
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
	hashedID, err := hashTokenIdentifier(tokenID)
	if err != nil {
		return AccessToken{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.accessTokenTTL())
	normalized := normalizeScopes(scopes)
	if _, err := exec.ExecContext(ctx, `
INSERT INTO oauth_access_tokens (token_id, client_id, user_id, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`, hashedID, clientID, userID, pq.StringArray(normalized), expires, now); err != nil {
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
	accessDigest, err := hashTokenIdentifier(accessTokenID)
	if err != nil {
		return "", time.Time{}, err
	}
	tokenID, err := generateOpaqueToken(48)
	if err != nil {
		return "", time.Time{}, err
	}
	hashedID, err := hashTokenIdentifier(tokenID)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.refreshTokenTTL())
	if _, err := exec.ExecContext(ctx, `
INSERT INTO oauth_refresh_tokens (token_id, access_token_id, client_id, user_id, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`, hashedID, accessDigest, clientID, userID, pq.StringArray(normalizeScopes(scopes)), expires, now); err != nil {
		return "", time.Time{}, err
	}
	return tokenID, expires, nil
}

func normalizeRedirectURIs(uris []string) ([]string, error) {
	set := make(map[string]struct{}, len(uris))
	for _, raw := range uris {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("oauth: invalid redirect URI %s", raw)
		}
		set[raw] = struct{}{}
	}
	if len(set) == 0 {
		return nil, errors.New("oauth: at least one redirect URI is required")
	}
	out := make([]string, 0, len(set))
	for uri := range set {
		out = append(out, uri)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeScopes(scopes []string) []string {
	set := make(map[string]struct{}, len(scopes)+1)
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	set["openid"] = struct{}{}
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
