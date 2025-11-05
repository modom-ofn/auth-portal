# AuthPortal Changelog

## v2.0.1

### Highlights
- Security: upgraded Go to 1.25.3 (addresses latest Go stdlib CVEs).
- New normalized `/whoami` endpoint with session metadata (issuedAt, expiry).
- Multi-provider identities table with safe backfill; reads prefer identities with legacy fallback.
- Provider layer refactor: return-value API with structured outcomes, dependency injection, and minimal health checks.
- Shared HTTP helpers with one retry on transient errors; unit tests for success/retry/decode paths.
- UI polish: consistent sign-in buttons; fixed Jellyfin icon sizing and label.
- LDAP: ldap-sync prefers identities; LDAP description now includes `provider=<name>` and `media_uuid=<uuid>`.

### Upgrade Notes
- Rebuild images to pull `golang:1.25.3-alpine3.21`.
- No manual DB migration required; schema/backfill for `identities` runs automatically at startup.
- Verify: sign in, call `/whoami` (authenticated=true), and confirm `identities` has rows.
