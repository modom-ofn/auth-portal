package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/lib/pq"
)

var (
	ldapHost     = os.Getenv("LDAP_HOST") // e.g. "openldap:389"
	ldapAdminDN  = "cn=admin,dc=plexauth,dc=local"
	ldapPassword = os.Getenv("LDAP_ADMIN_PASSWORD")
	baseDN       = "ou=users,dc=plexauth,dc=local"
)

func main() {
	db, err := sql.Open("postgres", "postgres://plexauth:plexpass@postgres:5432/plexauthdb?sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to Postgres: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT username, email FROM users")
	if err != nil {
		log.Fatalf("Failed to query users: %v", err)
	}
	defer rows.Close()

	l, err := ldap.Dial("tcp", ldapHost)
	if err != nil {
		log.Fatalf("LDAP connect error: %v", err)
	}
	defer l.Close()

	err = l.Bind(ldapAdminDN, ldapPassword)
	if err != nil {
		log.Fatalf("LDAP bind error: %v", err)
	}

	for rows.Next() {
		var username, email string
		if err := rows.Scan(&username, &email); err != nil {
			log.Printf("Error reading user row: %v", err)
			continue
		}

		log.Printf("Postgres user: username=%q, email=%q", username, email)

		if username == "" {
			log.Println("Skipping user with empty username.")
			continue
		}

		userDN := fmt.Sprintf("uid=%s,%s", username, baseDN)
		log.Printf("Creating LDAP entry: %s", userDN)

		// Check if user already exists
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
			fmt.Sprintf("(uid=%s)", username),
			[]string{"dn"},
			nil,
		)

		res, err := l.Search(req)
		if err != nil {
			log.Printf("Search error for %s: %v", username, err)
			continue
		}
		if len(res.Entries) > 0 {
			log.Printf("User %s already exists, skipping.", username)
			continue
		}

		// Create new entry
		addReq := ldap.NewAddRequest(userDN, nil)
		addReq.Attribute("objectClass", []string{"inetOrgPerson"})
		addReq.Attribute("uid", []string{username})
		addReq.Attribute("cn", []string{username})
		addReq.Attribute("sn", []string{"User"})
		addReq.Attribute("mail", []string{email})
		addReq.Attribute("userPassword", []string{"placeholder"}) // TODO: replace with hashed

		if err := l.Add(addReq); err != nil {
			log.Printf("Failed to add %s: %v", username, err)
		} else {
			log.Printf("Added user %s to LDAP", username)
		}
	}
}