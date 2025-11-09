package main

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"strings"
)

const (
	adminBootstrapUsersEnv   = "ADMIN_BOOTSTRAP_USERS"
	adminBootstrapGrantorEnv = "ADMIN_BOOTSTRAP_GRANTOR"
)

type bootstrapUser struct {
	Username string
	Email    string
}

func bootstrapAdminUsers() error {
	raw := strings.TrimSpace(os.Getenv(adminBootstrapUsersEnv))
	if raw == "" {
		return nil
	}

	grantor := strings.TrimSpace(os.Getenv(adminBootstrapGrantorEnv))
	if grantor == "" {
		grantor = "system:bootstrap"
	}

	users := parseBootstrapUsers(raw)
	if len(users) == 0 {
		log.Println("Admin bootstrap: no valid usernames found in ADMIN_BOOTSTRAP_USERS")
		return nil
	}

	var (
		granted []string
		joined  error
	)

	for _, entry := range users {
		username := strings.TrimSpace(entry.Username)
		email := strings.TrimSpace(entry.Email)
		if username == "" {
			continue
		}

		existing, err := getUserByUsername(username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				_, upsertErr := upsertUser(User{
					Username: username,
					Email:    nullStringFrom(email),
				})
				if upsertErr != nil {
					log.Printf("Admin bootstrap: failed to create user %q: %v", username, upsertErr)
					joined = errors.Join(joined, upsertErr)
					continue
				}
			} else {
				log.Printf("Admin bootstrap: lookup failed for %q: %v", username, err)
				joined = errors.Join(joined, err)
				continue
			}
		} else {
			if email != "" {
				existingEmail := ""
				if existing.Email.Valid {
					existingEmail = strings.TrimSpace(existing.Email.String)
				}
				if existingEmail != email {
					if _, upsertErr := upsertUser(User{
						Username: username,
						Email:    nullStringFrom(email),
					}); upsertErr != nil {
						log.Printf("Admin bootstrap: failed to update email for %q: %v", username, upsertErr)
						joined = errors.Join(joined, upsertErr)
						continue
					}
				}
			}

			if existing.IsAdmin {
				continue
			}
		}

		if err := setUserAdminByUsername(username, true, grantor); err != nil {
			log.Printf("Admin bootstrap: grant admin failed for %q: %v", username, err)
			joined = errors.Join(joined, err)
			continue
		}
		granted = append(granted, username)
	}

	if len(granted) > 0 {
		log.Printf("Admin bootstrap: granted admin to %d user(s): %s", len(granted), strings.Join(granted, ", "))
	} else {
		log.Println("Admin bootstrap: no new admin grants applied")
	}

	return joined
}

func parseBootstrapUsers(raw string) []bootstrapUser {
	parts := strings.Split(raw, ",")
	out := make([]bootstrapUser, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		username := part
		email := ""
		if strings.Contains(part, ":") {
			pieces := strings.SplitN(part, ":", 2)
			username = strings.TrimSpace(pieces[0])
			email = ""
			if len(pieces) > 1 {
				email = strings.TrimSpace(pieces[1])
			}
		}
		if username == "" {
			continue
		}
		out = append(out, bootstrapUser{
			Username: username,
			Email:    email,
		})
	}
	return out
}
