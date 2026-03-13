package ldapsync

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	defaultDBTimeout   = 8 * time.Second
	defaultLDAPTimeout = 10 * time.Second
)

var ErrRunInProgress = errors.New("ldap sync already running")

const managedByDescriptionValue = "managed_by=authportal"

type Config struct {
	LDAPHost           string `json:"ldapHost"`
	LDAPAdminDN        string `json:"ldapAdminDn"`
	LDAPAdminPassword  string `json:"ldapAdminPassword"`
	BaseDN             string `json:"baseDn"`
	LDAPStartTLS       bool   `json:"ldapStartTls"`
	DeleteStaleEntries bool   `json:"deleteStaleEntries"`
}

type Result struct {
	UsersConsidered int    `json:"usersConsidered"`
	EntriesAdded    int    `json:"entriesAdded"`
	EntriesUpdated  int    `json:"entriesUpdated"`
	EntriesDeleted  int    `json:"entriesDeleted"`
	FailedEntries   int    `json:"failedEntries"`
	Summary         string `json:"summary"`
}

type ConnectionTestResult struct {
	Connected       bool   `json:"connected"`
	Bound           bool   `json:"bound"`
	BaseDNExists    bool   `json:"baseDnExists"`
	BaseDNCreatable bool   `json:"baseDnCreatable"`
	Message         string `json:"message"`
}

type Status struct {
	Running       bool       `json:"running"`
	TriggeredBy   string     `json:"triggeredBy,omitempty"`
	StartedAt     *time.Time `json:"startedAt,omitempty"`
	FinishedAt    *time.Time `json:"finishedAt,omitempty"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastResult    Result     `json:"lastResult"`
}

type Service struct {
	db *sql.DB

	mu     sync.RWMutex
	status Status
}

type rowUser struct {
	Username string
	Email    sql.NullString
	idents   map[string]identityInfo
}

type identityInfo struct {
	Provider  string
	MediaUUID string
}

func NewService(db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, errors.New("ldap sync service requires db")
	}
	return &Service{db: db}, nil
}

func (s *Service) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneStatus(s.status)
}

func (s *Service) Run(ctx context.Context, cfg Config, actor string) (Result, error) {
	if err := ValidateConfig(cfg); err != nil {
		return Result{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	now := time.Now().UTC()
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return Result{}, ErrRunInProgress
	}
	s.status.Running = true
	s.status.TriggeredBy = strings.TrimSpace(actor)
	s.status.StartedAt = ptrTime(now)
	s.status.FinishedAt = nil
	s.status.LastError = ""
	s.mu.Unlock()

	result, runErr := s.run(ctx, cfg)

	finishedAt := time.Now().UTC()
	s.mu.Lock()
	s.status.Running = false
	s.status.FinishedAt = ptrTime(finishedAt)
	s.status.LastResult = result
	if runErr != nil {
		s.status.LastError = runErr.Error()
	} else {
		s.status.LastError = ""
		s.status.LastSuccessAt = ptrTime(finishedAt)
	}
	s.mu.Unlock()

	return result, runErr
}

func ValidateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.LDAPHost) == "" {
		return errors.New("ldap host is required")
	}
	if strings.TrimSpace(cfg.LDAPAdminDN) == "" {
		return errors.New("ldap admin DN is required")
	}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return errors.New("base DN is required")
	}
	return nil
}

func (s *Service) TestConnection(ctx context.Context, cfg Config) (ConnectionTestResult, error) {
	if err := ValidateConfig(cfg); err != nil {
		return ConnectionTestResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return ConnectionTestResult{}, fmt.Errorf("ldap connect error: %w", err)
	}
	defer conn.Close()

	result := ConnectionTestResult{Connected: true}
	if cfg.LDAPStartTLS {
		if err := conn.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12}); err != nil {
			return result, fmt.Errorf("ldap StartTLS error: %w", err)
		}
	}
	if err := conn.Bind(strings.TrimSpace(cfg.LDAPAdminDN), cfg.LDAPAdminPassword); err != nil {
		return result, fmt.Errorf("ldap bind error: %w", err)
	}
	result.Bound = true

	baseDN := strings.TrimSpace(cfg.BaseDN)
	exists, creatable, err := probeBaseDN(conn, baseDN)
	if err != nil {
		return result, err
	}
	result.BaseDNExists = exists
	result.BaseDNCreatable = creatable
	switch {
	case exists:
		result.Message = "LDAP connection successful. Base DN is reachable."
	case creatable:
		result.Message = "LDAP connection successful. Base DN does not exist yet, but it appears creatable."
	default:
		result.Message = "LDAP connection successful, but the configured Base DN is not reachable."
	}
	return result, nil
}

func (s *Service) run(ctx context.Context, cfg Config) (Result, error) {
	users, err := s.loadAuthorizedUsers(ctx)
	if err != nil {
		return Result{}, err
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return Result{}, fmt.Errorf("ldap connect error: %w", err)
	}
	defer conn.Close()

	baseDN := strings.TrimSpace(cfg.BaseDN)
	if err := prepareLDAPConnection(conn, cfg, baseDN); err != nil {
		return Result{}, err
	}

	result := Result{UsersConsidered: len(users)}
	s.syncAuthorizedUsers(conn, baseDN, users, &result)

	if cfg.DeleteStaleEntries {
		deleted, failed, err := deleteStaleManagedEntries(conn, strings.TrimSpace(cfg.BaseDN), users)
		result.EntriesDeleted += deleted
		result.FailedEntries += failed
		if err != nil {
			return result, err
		}
	}

	result.Summary = fmt.Sprintf(
		"%d users processed; %d added, %d updated, %d deleted, %d failed",
		result.UsersConsidered,
		result.EntriesAdded,
		result.EntriesUpdated,
		result.EntriesDeleted,
		result.FailedEntries,
	)
	log.Printf("LDAP sync completed: %s", result.Summary)
	return result, nil
}

func (s *Service) loadAuthorizedUsers(ctx context.Context) (map[string]*rowUser, error) {
	queryCtx, cancel := context.WithTimeout(ctx, defaultDBTimeout)
	defer cancel()

	var identitiesAvailable bool
	if err := s.db.QueryRowContext(queryCtx, `
SELECT EXISTS (
    SELECT 1
      FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = 'identities'
)`).Scan(&identitiesAvailable); err != nil {
		return nil, fmt.Errorf("identities table check failed: %w", err)
	}

	rows, useIdentities, queryErr := s.queryAuthorizedUsers(queryCtx, identitiesAvailable)
	if queryErr != nil {
		return nil, fmt.Errorf("query authorized users failed: %w", queryErr)
	}
	defer rows.Close()

	users := make(map[string]*rowUser)
	for rows.Next() {
		username, email, mediaUUID, provider, err := scanAuthorizedUserRow(rows, useIdentities)
		if err != nil {
			return nil, err
		}
		upsertAuthorizedUser(users, username, email, mediaUUID, provider)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authorized user rows error: %w", err)
	}
	return users, nil
}

func prepareLDAPConnection(conn *ldap.Conn, cfg Config, baseDN string) error {
	if cfg.LDAPStartTLS {
		if err := conn.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("ldap StartTLS error: %w", err)
		}
	}
	if err := conn.Bind(strings.TrimSpace(cfg.LDAPAdminDN), cfg.LDAPAdminPassword); err != nil {
		return fmt.Errorf("ldap bind error: %w", err)
	}
	if err := ensureOUExists(conn, baseDN); err != nil {
		return fmt.Errorf("ensure base DN failed: %w", err)
	}
	return nil
}

func (s *Service) syncAuthorizedUsers(conn *ldap.Conn, baseDN string, users map[string]*rowUser, result *Result) {
	usernames := make([]string, 0, len(users))
	for username := range users {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)

	for _, username := range usernames {
		entry := users[username]
		added, err := upsertLDAPEntry(conn, baseDN, entry)
		if err != nil {
			log.Printf("LDAP sync entry failed for %q: %v", username, err)
			result.FailedEntries++
			continue
		}
		if added {
			log.Printf("LDAP sync added entry for %q", username)
			result.EntriesAdded++
			continue
		}
		log.Printf("LDAP sync updated entry for %q", username)
		result.EntriesUpdated++
	}
}

func (s *Service) queryAuthorizedUsers(ctx context.Context, identitiesAvailable bool) (*sql.Rows, bool, error) {
	if identitiesAvailable {
		rows, err := s.db.QueryContext(ctx, `
SELECT u.username, u.email, i.media_uuid, i.provider
  FROM identities i
  JOIN users u ON u.id = i.user_id
 WHERE i.media_access = TRUE
 ORDER BY u.username, i.provider`)
		if err == nil {
			return rows, true, nil
		}
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT username, email, media_uuid
  FROM users
 WHERE media_access = TRUE
 ORDER BY username`)
	return rows, false, err
}

func scanAuthorizedUserRow(rows *sql.Rows, useIdentities bool) (string, sql.NullString, sql.NullString, string, error) {
	var (
		username  string
		email     sql.NullString
		mediaUUID sql.NullString
		provider  string
	)

	if useIdentities {
		if err := rows.Scan(&username, &email, &mediaUUID, &provider); err != nil {
			return "", sql.NullString{}, sql.NullString{}, "", fmt.Errorf("scan identities row failed: %w", err)
		}
		return username, email, mediaUUID, provider, nil
	}

	if err := rows.Scan(&username, &email, &mediaUUID); err != nil {
		return "", sql.NullString{}, sql.NullString{}, "", fmt.Errorf("scan users row failed: %w", err)
	}
	return username, email, mediaUUID, inferProviderFromUUID(mediaUUID.String), nil
}

func upsertAuthorizedUser(users map[string]*rowUser, username string, email, mediaUUID sql.NullString, provider string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	entry := users[username]
	if entry == nil {
		entry = &rowUser{Username: username}
		users[username] = entry
	}
	if normalized := normalizeNullString(email); normalized.Valid && !entry.Email.Valid {
		entry.Email = normalized
	}
	entry.addIdentity(provider, mediaUUID.String)
}

func (u *rowUser) addIdentity(provider, mediaUUID string) {
	provider = strings.TrimSpace(provider)
	mediaUUID = strings.TrimSpace(mediaUUID)
	if provider == "" && mediaUUID == "" {
		return
	}
	if u.idents == nil {
		u.idents = make(map[string]identityInfo)
	}
	key := provider + "\x00" + mediaUUID
	if _, exists := u.idents[key]; exists {
		return
	}
	u.idents[key] = identityInfo{Provider: provider, MediaUUID: mediaUUID}
}

func (u *rowUser) identityList() []identityInfo {
	if len(u.idents) == 0 {
		return nil
	}
	out := make([]identityInfo, 0, len(u.idents))
	for _, ident := range u.idents {
		out = append(out, ident)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return out[i].MediaUUID < out[j].MediaUUID
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func upsertLDAPEntry(conn *ldap.Conn, baseDN string, entry *rowUser) (bool, error) {
	userDN := fmt.Sprintf("uid=%s,%s", ldapEscape(entry.Username), baseDN)
	exists, err := entryExists(conn, baseDN, entry.Username)
	if err != nil {
		return false, err
	}

	mailVals := []string{}
	if entry.Email.Valid {
		mailVals = append(mailVals, entry.Email.String)
	}
	descVals := []string{}
	for _, ident := range entry.identityList() {
		if ident.Provider != "" {
			descVals = append(descVals, "provider="+ident.Provider)
		}
		if ident.MediaUUID != "" {
			descVals = append(descVals, "media_uuid="+ident.MediaUUID)
		}
	}
	descVals = appendIfMissing(descVals, managedByDescriptionValue)
	descVals = uniqueSortedStrings(descVals)

	if !exists {
		addReq := ldap.NewAddRequest(userDN, nil)
		addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
		addReq.Attribute("uid", []string{entry.Username})
		addReq.Attribute("cn", []string{entry.Username})
		addReq.Attribute("sn", []string{"User"})
		if len(mailVals) > 0 {
			addReq.Attribute("mail", mailVals)
		}
		if len(descVals) > 0 {
			addReq.Attribute("description", descVals)
		}
		return true, conn.Add(addReq)
	}

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("cn", []string{entry.Username})
	modReq.Replace("sn", []string{"User"})
	modReq.Replace("uid", []string{entry.Username})
	modReq.Replace("mail", mailVals)
	modReq.Replace("description", descVals)
	return false, conn.Modify(modReq)
}

func deleteStaleManagedEntries(conn *ldap.Conn, baseDN string, activeUsers map[string]*rowUser) (int, int, error) {
	managed, err := listManagedEntries(conn, baseDN)
	if err != nil {
		return 0, 0, fmt.Errorf("list managed ldap entries failed: %w", err)
	}
	deleted := 0
	failed := 0
	for username, dn := range managed {
		if _, ok := activeUsers[username]; ok {
			continue
		}
		delReq := ldap.NewDelRequest(dn, nil)
		if err := conn.Del(delReq); err != nil {
			log.Printf("LDAP sync stale delete failed for %q (%s): %v", username, dn, err)
			failed++
			continue
		}
		log.Printf("LDAP sync deleted stale entry for %q (%s)", username, dn)
		deleted++
	}
	return deleted, failed, nil
}

func listManagedEntries(conn *ldap.Conn, baseDN string) (map[string]string, error) {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(description=%s)", ldapEscapeFilterValue(managedByDescriptionValue)),
		[]string{"uid", "dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]string, len(res.Entries))
	for _, entry := range res.Entries {
		username := strings.TrimSpace(entry.GetAttributeValue("uid"))
		dn := strings.TrimSpace(entry.DN)
		if username == "" || dn == "" {
			continue
		}
		entries[username] = dn
	}
	return entries, nil
}

func dialLDAP(cfg Config) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: defaultLDAPTimeout}
	host := strings.TrimSpace(cfg.LDAPHost)
	if strings.HasPrefix(host, "ldap://") || strings.HasPrefix(host, "ldaps://") {
		return ldap.DialURL(host, ldap.DialWithDialer(dialer))
	}
	return ldap.DialURL("ldap://"+host, ldap.DialWithDialer(dialer))
}

func ensureOUExists(conn *ldap.Conn, baseDN string) error {
	lower := strings.ToLower(baseDN)
	if strings.HasPrefix(lower, "ou=") {
		exists, err := dnExists(conn, baseDN)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		addReq := ldap.NewAddRequest(baseDN, nil)
		addReq.Attribute("objectClass", []string{"top", "organizationalUnit"})
		if ou := firstRDNValue(lower, "ou"); ou != "" {
			addReq.Attribute("ou", []string{ou})
		}
		return conn.Add(addReq)
	}

	target := fmt.Sprintf("ou=users,%s", baseDN)
	exists, err := dnExists(conn, target)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	addReq := ldap.NewAddRequest(target, nil)
	addReq.Attribute("objectClass", []string{"top", "organizationalUnit"})
	addReq.Attribute("ou", []string{"users"})
	return conn.Add(addReq)
}

func probeBaseDN(conn *ldap.Conn, baseDN string) (bool, bool, error) {
	lower := strings.ToLower(baseDN)
	if strings.HasPrefix(lower, "ou=") {
		exists, err := dnExists(conn, baseDN)
		if err != nil {
			return false, false, fmt.Errorf("base DN lookup failed: %w", err)
		}
		if exists {
			return true, false, nil
		}
		parent := parentDN(baseDN)
		if strings.TrimSpace(parent) == "" {
			return false, false, nil
		}
		parentExists, err := dnExists(conn, parent)
		if err != nil {
			return false, false, fmt.Errorf("base DN parent lookup failed: %w", err)
		}
		return false, parentExists, nil
	}

	exists, err := dnExists(conn, baseDN)
	if err != nil {
		return false, false, fmt.Errorf("base DN lookup failed: %w", err)
	}
	return exists, false, nil
}

func dnExists(conn *ldap.Conn, dn string) (bool, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, err
	}
	return len(res.Entries) > 0, nil
}

func entryExists(conn *ldap.Conn, baseDN, username string) (bool, error) {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(uid=%s)", ldapEscape(username)),
		[]string{"dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return false, err
	}
	return len(res.Entries) > 0, nil
}

func ldapEscape(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
	)
	return replacer.Replace(value)
}

func ldapEscapeFilterValue(value string) string {
	return ldap.EscapeFilter(value)
}

func inferProviderFromUUID(value string) string {
	raw := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(raw, "plex-"):
		return "plex"
	case strings.HasPrefix(raw, "emby-"):
		return "emby"
	case strings.HasPrefix(raw, "jellyfin-"):
		return "jellyfin"
	default:
		return ""
	}
}

func firstRDNValue(dnLower, key string) string {
	parts := strings.Split(dnLower, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(part, key+"="))
		}
	}
	return ""
}

func parentDN(value string) string {
	parts := strings.SplitN(value, ",", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func normalizeNullString(ns sql.NullString) sql.NullString {
	if !ns.Valid {
		return sql.NullString{}
	}
	trimmed := strings.TrimSpace(ns.String)
	if trimmed == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: trimmed, Valid: true}
}

func cloneStatus(src Status) Status {
	dst := src
	dst.StartedAt = cloneTimePtr(src.StartedAt)
	dst.FinishedAt = cloneTimePtr(src.FinishedAt)
	dst.LastSuccessAt = cloneTimePtr(src.LastSuccessAt)
	return dst
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.UTC()
	return &copied
}

func ptrTime(value time.Time) *time.Time {
	copied := value.UTC()
	return &copied
}

func appendIfMissing(values []string, target string) []string {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return values
		}
	}
	return append(values, target)
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
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
