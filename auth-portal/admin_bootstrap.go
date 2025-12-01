package main

import (
	"database/sql"
	"errors"
	"fmt"
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

	granted, joined := applyBootstrapUsers(users, grantor)
	logBootstrapOutcome(granted)
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

func applyBootstrapUsers(users []bootstrapUser, grantor string) ([]string, error) {
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

		grantedUser, err := processBootstrapUser(username, email, grantor)
		if err != nil {
			log.Printf("Admin bootstrap: %v", err)
			joined = errors.Join(joined, err)
			continue
		}
		if grantedUser {
			granted = append(granted, username)
		}
	}

	return granted, joined
}

func processBootstrapUser(username, email, grantor string) (bool, error) {
	isAdmin, err := ensureBootstrapUser(username, email)
	if err != nil {
		return false, err
	}
	if isAdmin {
		return false, nil
	}

	if err := setUserAdminByUsername(username, true, grantor); err != nil {
		return false, fmt.Errorf("grant admin failed for %q: %w", username, err)
	}
	return true, nil
}

func ensureBootstrapUser(username, email string) (bool, error) {
	existing, err := getUserByUsername(username)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("lookup failed for %q: %w", username, err)
		}
		if _, upsertErr := upsertUser(User{
			Username: username,
			Email:    nullStringFrom(email),
		}); upsertErr != nil {
			return false, fmt.Errorf("failed to create user %q: %w", username, upsertErr)
		}
		return false, nil
	}

	if shouldUpdateEmail(existing.Email, email) {
		if _, upsertErr := upsertUser(User{
			Username: username,
			Email:    nullStringFrom(email),
		}); upsertErr != nil {
			return existing.IsAdmin, fmt.Errorf("failed to update email for %q: %w", username, upsertErr)
		}
	}

	return existing.IsAdmin, nil
}

func shouldUpdateEmail(existing sql.NullString, newEmail string) bool {
	newEmail = strings.TrimSpace(newEmail)
	if newEmail == "" {
		return false
	}
	current := ""
	if existing.Valid {
		current = strings.TrimSpace(existing.String)
	}
	return current != newEmail
}

func logBootstrapOutcome(granted []string) {
	if len(granted) == 0 {
		log.Println("Admin bootstrap: no new admin grants applied")
		return
	}
	log.Printf("Admin bootstrap: granted admin to %d user(s): %s", len(granted), strings.Join(granted, ", "))
}
