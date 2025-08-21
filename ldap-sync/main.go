package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/lib/pq"
)

var (
	// Postgres
	dbURL = envOr("DATABASE_URL", "postgres://plexauth:plexpass@postgres:5432/plexauthdb?sslmode=disable")

	// LDAP
	ldapHost     = envOr("LDAP_HOST", "ldap://openldap:389") // supports ldap:// or ldaps://
	ldapAdminDN  = envOr("LDAP_ADMIN_DN", "cn=admin,dc=plexauth,dc=local")
	ldapPassword = envOr("LDAP_ADMIN_PASSWORD", "")
	baseDN       = envOr("BASE_DN", "ou=users,dc=plexauth,dc=local")
	startTLS     = strings.EqualFold(envOr("LDAP_STARTTLS", "false"), "true")

	// Timeouts
	dbTimeout   = 8 * time.Second
	ldapTimeout = 10 * time.Second
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type rowUser struct {
	Username string
	Email    sql.NullString
	PlexUUID sql.NullString
}

func main() {
	// ---- Postgres
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("postgres open: %v", err)
	}
	defer db.Close()

	{
		ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			log.Fatalf("postgres ping: %v", err)
		}
	}

	// Only sync authorized users
	const q = `
SELECT username, email, plex_uuid
FROM users
WHERE plex_access = TRUE
ORDER BY username
`
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		log.Fatalf("query users: %v", err)
	}
	defer rows.Close()

	// ---- LDAP connect & bind
	l, err := dialLDAP(ldapHost)
	if err != nil {
		log.Fatalf("LDAP connect error: %v", err)
	}
	defer l.Close()

	if startTLS {
		if err := l.StartTLS(nil); err != nil {
			log.Fatalf("LDAP StartTLS error: %v", err)
		}
	}

	if err := l.Bind(ldapAdminDN, ldapPassword); err != nil {
		log.Fatalf("LDAP bind error: %v", err)
	}

	// Ensure base OU exists, create it if needed
	if err := ensureOUExists(l, baseDN); err != nil {
		log.Fatalf("ensureOUExists(%s): %v", baseDN, err)
	}

	// Process rows
	for rows.Next() {
		var u rowUser
		if err := rows.Scan(&u.Username, &u.Email, &u.PlexUUID); err != nil {
			log.Printf("scan row: %v", err)
			continue
		}

		username := strings.TrimSpace(u.Username)
		if username == "" {
			log.Println("skipping user with empty username")
			continue
		}

		// Build DN
		userDN := fmt.Sprintf("uid=%s,%s", ldapEscape(username), baseDN)

		// Read existing entry (if any)
		exists, err := entryExists(l, baseDN, username)
		if err != nil {
			log.Printf("LDAP search error for %s: %v", username, err)
			continue
		}

		if !exists {
			// Add new inetOrgPerson (include standard aux classes for compatibility)
			addReq := ldap.NewAddRequest(userDN, nil)
			addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
			addReq.Attribute("uid", []string{username})
			addReq.Attribute("cn", []string{username})
			addReq.Attribute("sn", []string{"User"})

			if u.Email.Valid && strings.TrimSpace(u.Email.String) != "" {
				addReq.Attribute("mail", []string{strings.TrimSpace(u.Email.String)})
			}
			if u.PlexUUID.Valid && strings.TrimSpace(u.PlexUUID.String) != "" {
				addReq.Attribute("description", []string{"plex_uuid=" + strings.TrimSpace(u.PlexUUID.String)})
			}
			// You can set a placeholder password or leave it absent if downstream apps bind anonymously and only search.
			// addReq.Attribute("userPassword", []string{"{SSHA}placeholder"})

			if err := l.Add(addReq); err != nil {
				log.Printf("LDAP add %s: %v", userDN, err)
				continue
			}
			log.Printf("LDAP added: %s", userDN)
			continue
		}

		// Modify existing
		modReq := ldap.NewModifyRequest(userDN, nil)
		// Replace/ensure required attributes
		modReq.Replace("cn", []string{username})
		modReq.Replace("sn", []string{"User"})
		modReq.Replace("uid", []string{username})

		// Optional fields
		if u.Email.Valid && strings.TrimSpace(u.Email.String) != "" {
			modReq.Replace("mail", []string{strings.TrimSpace(u.Email.String)})
		} else {
			modReq.Replace("mail", []string{})
		}
		if u.PlexUUID.Valid && strings.TrimSpace(u.PlexUUID.String) != "" {
			modReq.Replace("description", []string{"plex_uuid=" + strings.TrimSpace(u.PlexUUID.String)})
		} else {
			modReq.Replace("description", []string{})
		}

		if err := l.Modify(modReq); err != nil {
			log.Printf("LDAP modify %s: %v", userDN, err)
			continue
		}
		log.Printf("LDAP updated: %s", userDN)
	}

	if err := rows.Err(); err != nil {
		log.Printf("rows error: %v", err)
	}
}

// dialLDAP supports ldap:// and ldaps://, or host:port (plain)
func dialLDAP(host string) (*ldap.Conn, error) {
	d := &net.Dialer{Timeout: ldapTimeout}
	if strings.HasPrefix(host, "ldap://") || strings.HasPrefix(host, "ldaps://") {
		return ldap.DialURL(host, ldap.DialWithDialer(d))
	}
	return ldap.DialURL("ldap://"+host, ldap.DialWithDialer(d))
}

// --- helpers ---

// ensureOUExists creates the OU branch if missing.
// Supports either "ou=users,dc=..." or "dc=a,dc=b" base with an OU under it.
func ensureOUExists(l *ldap.Conn, base string) error {
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