package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ldapSyncResult struct {
	StartedAt     time.Time `json:"startedAt"`
	FinishedAt    time.Time `json:"finishedAt,omitempty"`
	DurationMs    int64     `json:"durationMs"`
	Added         int       `json:"added"`
	Updated       int       `json:"updated"`
	Skipped       int       `json:"skipped"`
	GroupsUpdated int       `json:"groupsUpdated"`
	Success       bool      `json:"success"`
	Message       string    `json:"message,omitempty"`
}

type ldapSyncState struct {
	mu      sync.Mutex
	running bool
	last    ldapSyncResult
}

var ldapState ldapSyncState

const (
	ldapTimeout = 10 * time.Second
)

type ldapSyncUser struct {
	Username   string
	Email      string
	Identities []identityInfo
	Roles      []string
}

type identityInfo struct {
	Provider  string
	MediaUUID string
}

func runLDAPSync(ctx context.Context, cfg LDAPConfig) ldapSyncResult {
	start := time.Now().UTC()
	result := ldapSyncResult{
		StartedAt: start,
	}

	if !cfg.Enabled {
		result.Success = false
		result.Message = "LDAP sync disabled"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if err := validateLDAPConfig(cfg); err != nil {
		result.Success = false
		result.Message = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	users, err := collectLDAPUsers(ctx)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("load users: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	conn, err := dialLDAP(cfg.Host, cfg.StartTLS)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("ldap dial: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	defer conn.Close()

	if err := conn.Bind(cfg.AdminDN, cfg.Password); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("ldap bind failed: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	if err := ensureOUExists(conn, cfg.BaseDN); err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("ensure base OU: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if cfg.GroupBaseDN != "" {
		if err := ensureOUExists(conn, cfg.GroupBaseDN); err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("ensure group OU: %v", err)
			result.FinishedAt = time.Now().UTC()
			return result
		}
	}

	for _, u := range users {
		userDN := fmt.Sprintf("uid=%s,%s", ldapEscape(u.Username), cfg.BaseDN)
		exists, err := entryExists(conn, cfg.BaseDN, u.Username)
		if err != nil {
			log.Printf("ldap search failed for %s: %v", u.Username, err)
			result.Skipped++
			continue
		}

		mailVals := []string{}
		if u.Email != "" {
			mailVals = append(mailVals, u.Email)
		}
		descVals := []string{}
		for _, ident := range u.Identities {
			if ident.Provider != "" {
				descVals = append(descVals, "provider="+ident.Provider)
			}
			if ident.MediaUUID != "" {
				descVals = append(descVals, "media_uuid="+ident.MediaUUID)
			}
		}

		if !exists {
			addReq := ldap.NewAddRequest(userDN, nil)
			addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
			addReq.Attribute("uid", []string{u.Username})
			addReq.Attribute("cn", []string{u.Username})
			addReq.Attribute("sn", []string{"User"})
			if len(mailVals) > 0 {
				addReq.Attribute("mail", mailVals)
			}
			if len(descVals) > 0 {
				addReq.Attribute("description", descVals)
			}
			if err := conn.Add(addReq); err != nil {
				log.Printf("ldap add %s: %v", userDN, err)
				result.Skipped++
				continue
			}
			result.Added++
			continue
		}

		modReq := ldap.NewModifyRequest(userDN, nil)
		modReq.Replace("cn", []string{u.Username})
		modReq.Replace("sn", []string{"User"})
		modReq.Replace("uid", []string{u.Username})
		modReq.Replace("mail", mailVals)
		modReq.Replace("description", descVals)
		if err := conn.Modify(modReq); err != nil {
			log.Printf("ldap modify %s: %v", userDN, err)
			result.Skipped++
			continue
		}
		result.Updated++
	}

	groupUpdates, err := syncLDAPGroups(conn, cfg, users)
	if err != nil {
		log.Printf("ldap group sync error: %v", err)
		if result.Message == "" {
			result.Message = err.Error()
		}
	}
	result.GroupsUpdated = groupUpdates

	result.Success = result.Message == ""
	result.FinishedAt = time.Now().UTC()
	result.DurationMs = result.FinishedAt.Sub(start).Milliseconds()
	if result.Success && result.Message == "" {
		result.Message = "ldap sync completed"
	}
	return result
}

func collectLDAPUsers(ctx context.Context) ([]ldapSyncUser, error) {
	users, err := loadAdminUsers(ctx)
	if err != nil {
		return nil, err
	}

	var out []ldapSyncUser
	for _, u := range users {
		if !u.MediaAccess {
			continue
		}
		username := strings.TrimSpace(u.Username)
		if username == "" {
			continue
		}
		entry := ldapSyncUser{
			Username: username,
			Email:    strings.TrimSpace(u.Email),
			Roles:    normalizePermissions(u.Roles),
		}
		for _, prov := range u.Providers {
			entry.Identities = append(entry.Identities, identityInfo{
				Provider:  strings.TrimSpace(prov.Provider),
				MediaUUID: strings.TrimSpace(prov.MediaUUID),
			})
		}
		out = append(out, entry)
	}
	return out, nil
}

func syncLDAPGroups(conn *ldap.Conn, cfg LDAPConfig, users []ldapSyncUser) (int, error) {
	if len(cfg.GroupRoleMappings) == 0 || cfg.GroupBaseDN == "" {
		return 0, nil
	}

	roleToUsers := make(map[string][]string)
	for _, u := range users {
		userDN := fmt.Sprintf("uid=%s,%s", ldapEscape(u.Username), cfg.BaseDN)
		for _, role := range u.Roles {
			roleToUsers[strings.ToLower(role)] = append(roleToUsers[strings.ToLower(role)], userDN)
		}
	}

	updated := 0
	for _, mapping := range cfg.GroupRoleMappings {
		roleKey := strings.ToLower(strings.TrimSpace(mapping.Role))
		if roleKey == "" || strings.TrimSpace(mapping.GroupCN) == "" {
			continue
		}
		members := dedupeStrings(roleToUsers[roleKey])
		groupDN := fmt.Sprintf("cn=%s,%s", ldapEscape(mapping.GroupCN), cfg.GroupBaseDN)
		if len(members) == 0 {
			// If group exists with no members, delete to avoid stale memberships.
			exists, err := dnExists(conn, groupDN)
			if err != nil {
				return updated, err
			}
			if exists {
				if err := conn.Del(ldap.NewDelRequest(groupDN, nil)); err != nil {
					return updated, err
				}
				updated++
			}
			continue
		}

		exists, err := dnExists(conn, groupDN)
		if err != nil {
			return updated, err
		}
		if !exists {
			req := ldap.NewAddRequest(groupDN, nil)
			req.Attribute("objectClass", []string{"top", "groupOfNames"})
			req.Attribute("cn", []string{mapping.GroupCN})
			req.Attribute("member", members)
			if err := conn.Add(req); err != nil {
				return updated, err
			}
			updated++
			continue
		}

		modReq := ldap.NewModifyRequest(groupDN, nil)
		modReq.Replace("member", members)
		if err := conn.Modify(modReq); err != nil {
			return updated, err
		}
		updated++
	}

	return updated, nil
}

// dialLDAP supports ldap:// and ldaps://, or host:port (plain)
func dialLDAP(host string, startTLS bool) (*ldap.Conn, error) {
	d := &net.Dialer{Timeout: ldapTimeout}
	if strings.HasPrefix(host, "ldap://") || strings.HasPrefix(host, "ldaps://") {
		conn, err := ldap.DialURL(host, ldap.DialWithDialer(d))
		if err != nil {
			return nil, err
		}
		if startTLS {
			if err := conn.StartTLS(nil); err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	conn, err := ldap.DialURL("ldap://"+host, ldap.DialWithDialer(d))
	if err != nil {
		return nil, err
	}
	if startTLS {
		if err := conn.StartTLS(nil); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// ensureOUExists creates the OU branch if missing.
// Supports either "ou=users,dc=..." or "dc=a,dc=b" base with an OU under it.
func ensureOUExists(l *ldap.Conn, base string) error {
	base = strings.TrimSpace(base)
	if base == "" {
		return errors.New("base dn is required")
	}
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "ou=") {
		exists, err := dnExists(l, base)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		add := ldap.NewAddRequest(base, nil)
		add.Attribute("objectClass", []string{"top", "organizationalUnit"})
		if ou := firstRDNValue(lower, "ou"); ou != "" {
			add.Attribute("ou", []string{ou})
		}
		return l.Add(add)
	}

	target := fmt.Sprintf("ou=users,%s", base)
	exists, err := dnExists(l, target)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	add := ldap.NewAddRequest(target, nil)
	add.Attribute("objectClass", []string{"top", "organizationalUnit"})
	add.Attribute("ou", []string{"users"})
	return l.Add(add)
}

func dnExists(l *ldap.Conn, dn string) (bool, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, err
	}
	return len(res.Entries) > 0, nil
}

func entryExists(l *ldap.Conn, base, username string) (bool, error) {
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(uid=%s)", ldapEscape(username)),
		[]string{"dn"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil {
		return false, err
	}
	return len(res.Entries) > 0, nil
}

// ldapEscape is a minimal DN/Filter value escape for uid usage in filters/DNs.
func ldapEscape(s string) string {
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
		",", "\\2c",
		"+", "\\2b",
		"\"", "\\22",
		"<", "\\3c",
		">", "\\3e",
		";", "\\3b",
		"=", "\\3d",
		"#", "\\23",
	)
	return replacer.Replace(s)
}

func firstRDNValue(dnLower, key string) string {
	parts := strings.Split(dnLower, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(p, key+"="))
		}
	}
	return ""
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
