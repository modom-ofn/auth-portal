package configstore

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStrictVersionAndDependentTransaction(t *testing.T) {
	for _, tc := range []struct {
		name        string
		current     int64
		expected    int64
		hookFailure bool
		conflict    bool
	}{
		{"zero cannot overwrite existing", 1, 0, false, true},
		{"stale version rejected", 2, 1, false, true},
		{"dependent failure rolls back config and audit", 1, 1, true, false},
		{"matching version commits dependent changes", 1, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer testDB.Close()
			columns := []string{"namespace", "key", "value", "version", "updated_at", "updated_by"}
			mock.ExpectQuery("SELECT namespace, key, value").WillReturnRows(sqlmock.NewRows(columns))
			store, err := New(testDB, Options{})
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectBegin()
			mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("policy", SectionDocumentKey).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery("SELECT version").WithArgs("policy", SectionDocumentKey).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(tc.current))
			called := false
			if tc.conflict {
				mock.ExpectRollback()
			} else {
				mock.ExpectExec("INSERT INTO app_config ").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("INSERT INTO app_config_history").WillReturnResult(sqlmock.NewResult(0, 1))
				if tc.hookFailure {
					mock.ExpectRollback()
				} else {
					mock.ExpectCommit()
					mock.ExpectQuery("SELECT namespace, key, value").WillReturnRows(sqlmock.NewRows(columns).AddRow("policy", SectionDocumentKey, []byte(`{}`), tc.current+1, time.Now(), "test"))
				}
			}
			_, err = store.UpsertSection(context.Background(), Section("policy"), struct{}{}, UpdateOptions{
				RequireVersion: true, ExpectVersion: tc.expected, BeforeCommit: func(context.Context, *sql.Tx) error {
					called = true
					if tc.hookFailure {
						return errors.New("cleanup failed")
					}
					return nil
				},
			})
			if tc.conflict && !errors.Is(err, ErrVersionMismatch) {
				t.Fatal(err)
			}
			if tc.hookFailure && err == nil {
				t.Fatal("dependent failure committed")
			}
			if !tc.conflict && !tc.hookFailure && err != nil {
				t.Fatal(err)
			}
			if called == tc.conflict {
				t.Fatal("hook execution did not follow version validation")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
