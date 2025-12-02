# AuthPortal Changelog

## v2.0.3

### Highlights
- Introduced the admin console with JSON-backed Providers/Security/MFA configuration, optimistic locking, change history, and inline editing at `/admin`.
- Added OAuth client management UI plus `/api/admin/oauth/*` endpoints (list/create/update/delete/rotate) to control authorization-server registrations.
- Shipped a first-party OAuth 2.1 / OpenID Connect authorization server featuring discovery, PKCE, consent tracking, RS256-signed ID tokens (with nonce), and refresh-token rotation gated on `offline_access`.
- Normalized time handling by introducing `APP_TIMEZONE`/`TZ`; backup schedules, last/next run timestamps, and the admin UI now display in your configured zone instead of UTC-only.
- Hardened popup completion flows by removing inline scripts and finishing the `window.opener` handoff inside `login.js`, keeping the stricter `script-src 'self'` CSP while preserving the Plex/Emby/Jellyfin sign-in UX.
- CI/CD now runs an Aqua Trivy scan immediately after multi-arch image builds to block CRITICAL/HIGH vulnerabilities before publishing Docker tags or GitHub releases.

### Upgrade Notes
- Define at least one bootstrap administrator with `ADMIN_BOOTSTRAP_USERS` (`username:email` pairs). Additional admins can be granted through the console later.
- Provide signing material via `OIDC_SIGNING_KEY_PATH` (preferred) or `OIDC_SIGNING_KEY`; set `OIDC_ISSUER` when the public issuer differs from `APP_BASE_URL`.
- Database migrations automatically add `config_store` entries and extend `oauth_auth_codes` with a `nonce` column-no manual steps required.
- The OAuth token endpoint now issues refresh tokens only when `offline_access` is requested; update downstream clients if they previously assumed implicit refresh support.
- Set `APP_TIMEZONE` (plus matching `TZ` in Docker) to keep scheduled backups and admin timestamps consistent with your locality; the compose/README samples now include these vars.
- Rebuild or pull the v2.0.3 image so you pick up the CSP-safe popup flow—older binaries with inline scripts will be blocked by modern browsers when `script-src 'self'` is enforced.

## v2.0.2

### Highlights
- Introduced TOTP-based multi-factor authentication with enrollment, verification, and challenge flows, plus recovery codes for break-glass access.
- Hardened session handling: pending-MFA cookies, configurable `SESSION_COOKIE_DOMAIN`, stricter SameSite/Secure defaults, and consistent JWT rotation once MFA succeeds.
- Added same-origin CSRF checks to sensitive POST routes and unified client IP detection for logging and security features.
- Implemented shared per-IP rate limiting middleware covering login, MFA, and logout endpoints.
- Updated UI assets and templates to expose MFA enrollment/challenge experiences in the portal.
- Upgraded build stack: Go 1.25.5 base image with patched OpenSSL 3.3.5 and BusyBox fixes.

### Upgrade Notes
- Rebuild images to pull `modomofn/auth-portal:v2.0.2` (Go 1.25.5 base with patched OpenSSL 3.3.5 and BusyBox).
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
