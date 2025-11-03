# AuthPortal Changelog

## v2.0.2

### Highlights
- Introduced TOTP-based multi-factor authentication with enrollment, verification, and challenge flows, plus recovery codes for break-glass access.
- Hardened session handling: pending-MFA cookies, configurable `SESSION_COOKIE_DOMAIN`, stricter SameSite/Secure defaults, and consistent JWT rotation once MFA succeeds.
- Added same-origin CSRF checks to sensitive POST routes and unified client IP detection for logging and security features.
- Implemented shared per-IP rate limiting middleware covering login, MFA, and logout endpoints.
- Updated UI assets and templates to expose MFA enrollment/challenge experiences in the portal.
- Upgraded build stack: Go 1.25.3 base image with patched OpenSSL 3.3.5 and BusyBox fixes.

### Upgrade Notes
- Rebuild images to pull `modomofn/auth-portal:v2.0.2` (Go 1.25.3 base with patched OpenSSL 3.3.5 and BusyBox).
- Database migrations run automatically at startup to create `user_mfa` and `user_mfa_recovery_codes` tables and related columns.
- Set `SESSION_COOKIE_DOMAIN` to the host scope you serve AuthPortal from so cookies survive redirects behind proxies.
- New environment toggles control MFA behaviour: `MFA_ENABLE`, `MFA_ENFORCE`, and `MFA_ISSUER` (defaults provided).
- Rate limiting currently uses built-in defaults (login: burst 5, ~10 req/min; MFA: burst 3, ~5 req/min); adjust the middleware if you need different policies.


## v2.0.1

### Highlights
- Security: upgraded Go to 1.23.12 (addresses CE-2025-47906).
- New normalized `/whoami` endpoint with session metadata (issuedAt, expiry).
- Multi-provider identities table with safe backfill; reads prefer identities with legacy fallback.
- Provider layer refactor: return-value API with structured outcomes, dependency injection, and minimal health checks.
- Shared HTTP helpers with one retry on transient errors; unit tests for success/retry/decode paths.
- UI polish: consistent sign-in buttons; fixed Jellyfin icon sizing and label.
- LDAP: ldap-sync prefers identities; LDAP description now includes `provider=<name>` and `media_uuid=<uuid>`.

### Upgrade Notes
- Rebuild images to pull `golang:1.23.12-alpine3.21`.
- No manual DB migration required; schema/backfill for `identities` runs automatically at startup.
- Verify: sign in, call `/whoami` (authenticated=true), and confirm `identities` has rows.
