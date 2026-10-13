# Strict OIDC configuration foundation

Shared helpers provide bounded strict JSON, required change reasons and optimistic versions. `RequireVersion` opts into version-zero comparison and document advisory locking. `BeforeCommit` permits dependent writes in the configuration/history transaction. Existing configstore callers retain previous defaults. No admin feature is enabled by this foundation alone.

The shared browser API helper preserves same-origin credentials and consistent error handling. Feature branches consume these helpers.

Test with `go test -race ./...`; set `AUTHPORTAL_TEST_DATABASE_URL` only to a disposable PostgreSQL database to exercise schema-isolated concurrency/rollback tests. The branch CI supplies one.
