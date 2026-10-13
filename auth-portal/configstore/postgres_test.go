package configstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// This integration test creates and drops only its own temporary schema.
func TestPostgresPolicyTransactions(t *testing.T) {
	dsn := os.Getenv("AUTHPORTAL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL test connection not configured")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("oidc_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	testDB, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	for _, statement := range []string{
		`CREATE TABLE app_config(namespace text,key text,value jsonb,version bigint,updated_at timestamptz,updated_by text,PRIMARY KEY(namespace,key))`,
		`CREATE TABLE app_config_history(namespace text,key text,value jsonb,version bigint,updated_at timestamptz,updated_by text,change_reason text)`,
		`CREATE TABLE user_roles(source text,external_ref text)`,
		`INSERT INTO user_roles VALUES('manual','a'),('oidc-plex','a'),('oidc-plex','b')`,
	} {
		if _, err = testDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(testDB, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = store.UpsertSection(ctx, "roles", struct{}{}, UpdateOptions{RequireVersion: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.UpsertSection(ctx, "roles", struct{}{}, UpdateOptions{RequireVersion: true}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatal("zero overwrote existing version", err)
	}
	hook := func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE source='oidc-plex' AND external_ref='a'`)
		return err
	}
	if _, err = store.UpsertSection(ctx, "roles", struct{}{}, UpdateOptions{RequireVersion: true, ExpectVersion: 1, BeforeCommit: func(ctx context.Context, tx *sql.Tx) error {
		if err := hook(ctx, tx); err != nil {
			return err
		}
		return errors.New("injected failure")
	}}); err == nil {
		t.Fatal("failed cleanup committed")
	}
	var count int
	if err = testDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&count); err != nil || count != 3 {
		t.Fatal("rollback did not preserve bindings", count, err)
	}
	if _, err = store.UpsertSection(ctx, "roles", struct{}{}, UpdateOptions{RequireVersion: true, ExpectVersion: 1, BeforeCommit: hook}); err != nil {
		t.Fatal(err)
	}
	if err = testDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&count); err != nil || count != 2 {
		t.Fatal("cleanup touched unrelated bindings", count, err)
	}
	if err = testDB.QueryRow(`SELECT COUNT(*) FROM app_config_history WHERE namespace='roles'`).Scan(&count); err != nil || count != 2 {
		t.Fatal("failed save left audit record", count, err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.UpsertSection(ctx, "concurrent", struct{}{}, UpdateOptions{RequireVersion: true})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrVersionMismatch) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent creation was not serialized", success, conflict)
	}
}
