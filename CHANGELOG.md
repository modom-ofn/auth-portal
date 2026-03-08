# AuthPortal Changelog

## v2.0.4

### Highlights
- Refactored the admin UX into modular tab controllers so tab state/actions are isolated; fixes regressions where editing one tab could break others.
- Standardized Recent Changes into a shared module and aligned behavior/layout across config tabs and Backups, including reason capture for backup schedule updates.
- Replaced ad-hoc config JSON editing with structured form-driven editing in Admin for key sections, while preserving import/export JSON compatibility.
- Reworked OAuth client management UI from table rows to card-based presentation with detail modal workflows; retained edit, rotate-secret, and delete actions.
- Unified button interaction tokens/styles across admin and portal surfaces, with consistent action coloring and improved modal close-button interactions.
- Removed legacy help `?` popups and moved guidance into per-field hover help/tooltips for Providers, Security, MFA, and App Settings.
- Expanded Authorized User service buttons: add/remove/edit entries, per-button color selection, and removed legacy single-link behavior from both config and portal rendering.
- Simplified portal styling model to secure color-only controls (background + modal), removed custom image upload/mode paths, and cleaned related dead UI/API/backend code.
- Improved Plex web-login resilience under rate limiting (429 poll responses) to reduce false `Auth failed` outcomes during provider callback flow.
- Hardened container runtime base image from standard Alpine to `dhi.io/alpine-base:3.23-alpine3.23-dev`, and updated compose/dev defaults to build and run the hardened image path.
- Mitigated BusyBox CVE coverage gaps by enforcing `busybox>=1.37.0-r27` in both Docker build and runtime stages.
- Reduced backend cognitive complexity in high-traffic auth/router handlers (routing assembly, MFA verification/challenge, OIDC token grant, and provider forward flows) by extracting focused helper functions without behavior changes.
- Improved SonarQube maintainability posture by centralizing repeated auth literals (post-login redirects/messages, OIDC error codes/messages, MFA error payloads) and removing unnecessary temporary variables in conditional paths.

### Upgrade Notes
- Bump image tags/config references to `v2.0.4` and rebuild so you pick up the modular admin UX + hardened runtime image changes.
- Rebuild images after upgrading to ensure the BusyBox minimum (`>=1.37.0-r27`) is present in both builder and runtime layers.
- If you maintained portal background image settings in prior versions, note that `v2.0.4` enforces color-only portal styling; use `portalBackgroundColor` and `portalModalColor`.
- For local full-stack compose usage, the dev compose file now builds AuthPortal locally by default (`AUTH_PORTAL_IMAGE` can override the output tag).
- No manual database migration steps are required beyond normal startup migrations.

### Pre-release Scan Summary
- Image scanned: local hardened build (`auth-portal:hardened-test`), plus Go 1.26.1 validation image (`auth-portal:go1261-test`).
- Docker Scout: `0` HIGH/CRITICAL findings.
- Trivy: `0` HIGH/CRITICAL findings; after Go 1.26.1 bump, `0` findings across all severities.
- Grype: `0` findings (HIGH/CRITICAL and all-severity pass).
- Artifacts generated locally during validation: `scout-auth-portal.sarif`, `trivy-auth-portal*.json`, `grype-auth-portal*.json`.

## v2.0.3

### Highlights
- Introduced the admin console with JSON-backed Providers/Security/MFA configuration, optimistic locking, change history, and inline editing at `/admin`.
- Added OAuth client management UI plus `/api/admin/oauth/*` endpoints (list/create/update/delete/rotate) to control authorization-server registrations.
- Shipped a first-party OAuth 2.1 / OpenID Connect authorization server featuring discovery, PKCE, consent tracking, RS256-signed ID tokens (with nonce), and refresh-token rotation gated on `offline_access`.
- Normalized time handling by introducing `APP_TIMEZONE`/`TZ`; backup schedules, last/next run timestamps, and the admin UI now display in your configured zone instead of UTC-only.
- Hardened popup completion flows by removing inline scripts and finishing the `window.opener` handoff inside `login.js`, keeping the stricter `script-src 'self'` CSP while preserving the Plex/Emby/Jellyfin sign-in UX.
- CI/CD now runs an Aqua Trivy scan immediately after multi-arch image builds to block CRITICAL/HIGH vulnerabilities before publishing Docker tags or GitHub releases.
- Fixed OIDC continuation so unauthenticated `/oidc/authorize` requests are resumed after login and MFA instead of dropping users at `/home`.
- Corrected OIDC redirect error behavior to return standards-compliant callback redirects for valid absolute `redirect_uri` values.

### Upgrade Notes
- Define at least one bootstrap administrator with `ADMIN_BOOTSTRAP_USERS` (`username:email` pairs). Additional admins can be granted through the console later.
- Provide signing material via `OIDC_SIGNING_KEY_PATH` (preferred) or `OIDC_SIGNING_KEY`; set `OIDC_ISSUER` when the public issuer differs from `APP_BASE_URL`.
- Database migrations automatically add `config_store` entries and extend `oauth_auth_codes` with a `nonce` column-no manual steps required.
- The OAuth token endpoint now issues refresh tokens only when `offline_access` is requested; update downstream clients if they previously assumed implicit refresh support.
- Set `APP_TIMEZONE` (plus matching `TZ` in Docker) to keep scheduled backups and admin timestamps consistent with your locality; the compose/README samples now include these vars.
- Rebuild or pull the v2.0.3 image so you pick up the CSP-safe popup flow—older binaries with inline scripts will be blocked by modern browsers when `script-src 'self'` is enforced.
- For OIDC clients, ensure each `redirect_uri` exactly matches one of the registered client redirect URIs (including path/prefix and trailing slash).
- Optional: set `TRUSTED_REDIRECT_HOSTS` to an explicit allow-list if you want to restrict absolute OIDC callback hosts beyond per-client registration.

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
