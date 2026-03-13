# AuthPortal (v2.0.5)

[![Docker Pulls](https://img.shields.io/docker/pulls/modomofn/auth-portal.svg)](https://hub.docker.com/r/modomofn/auth-portal)
[![Docker Image Size](https://img.shields.io/docker/image-size/modomofn/auth-portal/latest)](https://hub.docker.com/r/modomofn/auth-portal)
[![Go Version](https://img.shields.io/badge/Go-1.26.1%2B-00ADD8?logo=go)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL3.0-green.svg)](https://github.com/modom-ofn/auth-portal?tab=GPL-3.0-1-ov-file#readme)
[![Vibe Coded](https://img.shields.io/badge/Vibe_Coded-OpenAI_Codex-purple)](https://developers.openai.com/codex/windows)

[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=modom-ofn_auth-portal&metric=alert_status)](https://sonarcloud.io/dashboard?id=modom-ofn_auth-portal)
[![SonarCloud Bugs](https://sonarcloud.io/api/project_badges/measure?project=modom-ofn_auth-portal&metric=bugs)](https://sonarcloud.io/component_measures?id=modom-ofn_auth-portal&metric=reliability_rating&view=list)
[![SonarCloud Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=modom-ofn_auth-portal&metric=vulnerabilities)](https://sonarcloud.io/project/security_hotspots?id=modom-ofn_auth-portal)
![Docker Scout](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/modom-ofn/auth-portal/badges/.github/badges/docker-scout.json)

**AuthPortal** is a lightweight, self-hosted authentication gateway built for Plex, Jellyfin, and Emby ecosystems. It provides a unified login experience for media-based communities and home-lab environments—issuing secure, signed sessions for use across your intranet portals and apps.

AuthPortal authenticates users directly against their connected media server accounts, seals the server tokens for reuse, and manages session lifecycle via HTTP-only cookies. Authorized users are directed to their personalized home page, while unrecognized users are served a restricted or “guest” view.

> [!IMPORTANT]
> **Use at your own risk.** This project leans on Vibe Coding practices - AI pair-programming, automated refactors, and rapid iteration. Treat releases as starting points - test, monitor, and adapt to your stack. AuthPortal remains an independent effort with no endorsement from Plex, Emby, or Jellyfin.

> [!NOTE]
> - Docker Hub: https://hub.docker.com/r/modomofn/auth-portal
> - GitHub Repo: https://github.com/modom-ofn/auth-portal

---

## Features

- **Unified login gateway**
  - Supports Plex authentication and Emby/Jellyfin username+password login
  - Responsive modal-style interface for seamless in-browser authentication

- **Secure session management**
  - Signed, HTTP-only JWT cookie for authorized sessions
  - Optional TOTP-based multi-factor authentication (with recovery codes)
  - Per-tenant MFA enforcement toggles

- **Enterprise-ready expansion**
  - Optional LDAP integration for downstream application SSO requirements
  - Extensible provider architecture

- **Lightweight deployment**
  - Single-binary, fully containerized service
  - Simple environment-variable configuration
  - Minimal external dependencies

- **Customizable experience**
  - Two distinct home pages: authorized vs. unauthorized
  - Dark, modern UI with branded login buttons

- **Runtime configuration & admin console**
  - Web-based editing of Providers, Security, MFA, App Settings, and LDAP Sync config with versioning and history
  - OAuth client management (list/create/update/delete + secret rotation) without leaving the browser
  - Config backup tab with manual exports, scheduled runs (hourly/daily/weekly), retention, and one-click restore/download actions

- **First-party OAuth 2.1 / OIDC**
  - Authorization-code + PKCE, optional `offline_access` refresh rotation, RS256-signed ID tokens
  - Discovery, JWKS, token, and userinfo endpoints ready for downstream apps and identity brokers

### UI Preview

<p align="center">
  <img src="./screenshots/ui-preview-rotating.gif" alt="Rotating AuthPortal UI preview banner showing authorized and unauthorized views, MFA flow, and admin tabs for providers, security, MFA, app settings, OAuth clients, LDAP Sync, and backups." />
</p>

Frame descriptions (alt text):
1. Authorized user home with service buttons and account summary.
2. Unauthorized user view with restricted/guest access messaging.
3. MFA enrollment screen showing TOTP setup and verification flow.
4. Signed-in flow after MFA challenge completion.
5. Admin Providers tab for Plex, Jellyfin, and Emby configuration.
6. Admin Security tab for session and authentication controls.
7. Admin MFA settings tab with enforcement and recovery options.
8. Admin App Settings tab for portal behavior and branding controls.
9. Admin OAuth Clients tab showing client cards and management actions.
10. Admin LDAP Sync tab with connection testing, scheduling, and run history.
11. Admin Backups tab with exports, scheduling, retention, and restore actions.

---

## Table of Contents

- [Features](#features)
- [What's New in v2.0.5](#whats-new-in-v205)
- [LDAP Sync](#ldap-sync)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Admin Console & Config Store (new in v2.0.4)](#admin-console--config-store-new-in-v204)
  - [LDAP Sync (new in v2.0.5)](#ldap-sync-new-in-v205)
  - [Backups](#backups)
  - [OAuth 2.1 / OIDC Authorization Server (new in v2.0.4)](#oauth-21--oidc-authorization-server-new-in-v204)
  - [Multi-factor authentication](#multi-factor-authentication)
  - [Plex](#plex)
  - [Jellyfin](#jellyfin)
  - [Emby](#emby)
- [Providers (Plex / Jellyfin / Emby)](#providers-plex--jellyfin--emby)
- [Security Notes](#security-notes)
- [Database](#database)
- [Build & Images](#build--images)
- [Logging](#logging)
- [HTTP Routes](#http-routes)
- [Frontend Bits](#frontend-bits)
- [How it works](#how-it-works)
- [Customization](#customization)
- [Security best practices](#security-best-practices)
- [Security scans and code analysis](#security-scans-and-code-analysis)
- [Contributing](#contributing)
- [License](#license)
- [Upgrade Guide (to v2.0.5)](#upgrade-guide-to-v205)

---

## What's New in v2.0.5

- **LDAP Sync is now first-class in AuthPortal:** the former standalone `ldap-sync` companion workflow is replaced by a built-in `LDAP Sync` admin tab with persisted runtime config.
- **Manual and scheduled LDAP sync runs:** run syncs on demand or on an hourly/daily/weekly schedule directly from the admin console, with next-run calculation and persisted run history.
- **Connection validation before save/run:** test LDAP connectivity, bind credentials, and Base DN reachability from the UI before committing config.
- **Safe stale-entry cleanup:** optional deletion of stale LDAP records now only targets entries previously marked as AuthPortal-managed under the configured Base DN.
- **Improved LDAP observability and UX:** per-user sync failures are logged with the affected username, completion summaries are logged per run, and the admin panel now exposes structured connection-test results, Recent Changes integration, and a cleaner sectioned layout.
- **OpenLDAP bootstrap simplification:** the old `ldap-seed` helper is no longer part of the recommended workflow because AuthPortal can create the configured Base DN when it is missing and creatable.

## What's New in v2.0.4

- **Admin UX modularization and tab isolation:** refactored section logic into module controllers so Providers, Security, MFA, App Settings, OAuth, and Backups no longer trample each other’s state.
- **Shared Recent Changes module:** standardized recent-changes behavior/presentation across tabs, including Backups schedule updates with required change reason support.
- **Form-first admin configuration:** replaced fragile raw JSON editing paths with normalized forms while preserving import/export compatibility for valid JSON backups.
- **OAuth client UX redesign:** migrated OAuth clients from table rows to card layout with detail modal actions (edit, rotate secret, delete) and consistent button behaviors.
- **Consistency and clarity improvements:** unified button styling tokens across admin/authorized/unauthorized pages; replaced legacy `?` help popups with per-field hover helper text.
- **Authorized User service buttons:** removed legacy single-link fields, added add/remove/edit support with per-button colors, and updated authorized portal rendering to only use service-button entries.
- **Portal styling simplification:** removed custom image/mode upload flows and standardized to secure color-only controls for page background and modal color.
- **Provider login reliability hardening:** reduced Plex pin-polling failure behavior during 429 rate-limit windows to prevent stale popup flows ending in `Auth failed`.
- **Container hardening:** runtime image moved to `dhi.io/alpine-base:3.23-alpine3.23-dev`; compose defaults updated to local hardened builds.

---

## LDAP Sync

LDAP sync is built into AuthPortal in `v2.0.5`. Configure it in the Admin Console under `LDAP Sync` to run manual syncs or schedule recurring LDAP exports of authorized users.

What it does:

- Connects to LDAP with the configured host, bind DN, and password.
- Creates the configured Base DN when it is missing and creatable.
- Exports currently authorized AuthPortal users as LDAP entries.
- Supports manual sync and built-in hourly/daily/weekly scheduling.
- Records recent run history in the admin UI.
- Optionally deletes stale LDAP entries that were previously marked as managed by AuthPortal.

What changed from the old workflow:

- There is no longer a separate `ldap-sync` service or repo dependency in the recommended AuthPortal deployment path.
- The old `ldap-seed` helper for `ou=users` is no longer required for the default setup.
- LDAP sync configuration, change history, and schedule state now live with the rest of the AuthPortal admin/runtime config.

Operational notes:

- Use the `Test Connection` button before saving or running a sync.
- `Base DN Exists = PASS` means the target branch is already usable.
- `Base DN Exists = FAIL` and `Base DN Creatable = PASS` means AuthPortal should be able to create the branch on the first sync.
- `Base DN Exists = FAIL` and `Base DN Creatable = FAIL` means you need to fix the directory layout or LDAP ACLs first.
- Stale deletion only applies to entries previously stamped as AuthPortal-managed.

---

## Quick Start

1) **.env**

```env
# ---------- Core ----------
POSTGRES_PASSWORD=change-me-long-random
SESSION_SECRET=change-me-32+chars-random
SESSION_COOKIE_DOMAIN=yourdomain.com
APP_BASE_URL=http://localhost:8089

# Trusted proxy CIDR ranges for forwarded headers (comma separated; leave blank to disable)
TRUSTED_PROXY_CIDRS=

# Multi-factor authentication
MFA_ENABLE=1
MFA_ENFORCE=0
MFA_ISSUER=AuthPortal

# Authorized page extra link (optional)
LOGIN_EXTRA_LINK_URL=/some-internal-app
LOGIN_EXTRA_LINK_TEXT=Open Internal App

# Unauthorized page "Request Access" mailto link
UNAUTH_REQUEST_EMAIL=support@example.com
UNAUTH_REQUEST_SUBJECT=AuthPortal Access Request

# Set 'MEDIA_SERVER=' options: plex | emby | jellyfin
MEDIA_SERVER=plex

# Set 'FORCE_SECURE_COOKIE=1' in prod; if behind TLS/NGINX with X-Forwarded-Proto use 1
FORCE_SECURE_COOKIE=0
# Force HSTS headers even if APP_BASE_URL is http (set to 1 when TLS terminates upstream)
FORCE_HSTS=0
# Timezone (IANA name, e.g., America/New_York) used for schedules and timestamps
APP_TIMEZONE=UTC
# Container timezone (usually matches APP_TIMEZONE)
TZ=UTC

# 32-byte base64 key (e.g., openssl rand -base64 32) (Do Not Reuse Example Below)
DATA_KEY=5Z3UMPcF9BBkpB2SkuoXqYfGWKn1eXzpMdR8EyMV8dY=

# Admin bootstrap (comma-separated username:email pairs)
ADMIN_BOOTSTRAP_USERS=admin:admin@example.com

# OAuth2/OIDC signing & issuer (provide one of *_KEY or *_KEY_PATH)
OIDC_SIGNING_KEY_PATH=/run/secrets/oidc_signing_key.pem
OIDC_SIGNING_KEY=
OIDC_ISSUER=https://auth.example.com
# Optional allow-list for absolute OIDC redirect_uri hosts (comma/semicolon separated).
# If unset, AuthPortal trusts hosts from each client's registered redirect URIs.
TRUSTED_REDIRECT_HOSTS=

# Logging # DEBUG | INFO | WARN | ERROR
LOG_LEVEL=INFO

# ---------- LDAP Sync (optional; point to your existing LDAP server) ----------
LDAP_HOST=ldap://ldap.example.com:389
LDAP_ADMIN_DN=cn=admin,dc=authportal,dc=local
LDAP_ADMIN_PASSWORD=change-me-strong
BASE_DN=ou=users,dc=authportal,dc=local
LDAP_STARTTLS=false
LDAP_DELETE_STALE_ENTRIES=false
LDAP_SYNC_SCHEDULE_ENABLED=false
LDAP_SYNC_SCHEDULE_FREQUENCY=daily
LDAP_SYNC_SCHEDULE_TIME=02:15
LDAP_SYNC_SCHEDULE_DAY=sunday

# ---------- Plex ----------
# Optional but recommended for server-authorization checks
PLEX_OWNER_TOKEN=plxxxxxxxxxxxxxxxxxxxx

# Either set machine id or a server name (machine id wins if both present)
PLEX_SERVER_MACHINE_ID=
PLEX_SERVER_NAME=

# ---------- Emby ----------
EMBY_SERVER_URL=http://localhost:8096
EMBY_APP_NAME=AuthPortal
EMBY_APP_VERSION=2.0.5
# EMBY_API_KEY=
EMBY_OWNER_USERNAME=
EMBY_OWNER_ID=

# -------- Jellyfin ---------
JELLYFIN_SERVER_URL=http://localhost:8096
JELLYFIN_API_KEY=
JELLYFIN_APP_NAME=AuthPortal
JELLYFIN_APP_VERSION=2.0.5
```


2) **docker-compose.yaml**

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:15
    restart: unless-stopped
    environment:
      POSTGRES_DB: authportaldb
      POSTGRES_USER: authportal
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set-in-.env}
      # reuse same flag as app
      LOG_LEVEL: ${LOG_LEVEL:-INFO}
      TZ: ${TZ:-UTC}
    command:
      - sh
      - -c
      - |
        set -e
        case "${LOG_LEVEL:-INFO}" in
          DEBUG|debug)
            EXTRA="-c log_min_messages=debug1 -c log_connections=on -c log_disconnections=on -c log_destination=stderr"
            ;;
          INFO|info)
            EXTRA="-c log_min_messages=info -c log_destination=stderr"
            ;;
          WARN|warn|WARNING|warning)
            EXTRA="-c log_min_messages=warning -c log_destination=stderr"
            ;;
          ERROR|error)
            EXTRA="-c log_min_messages=error -c log_destination=stderr"
            ;;
          *)
            EXTRA="-c log_min_messages=warning -c log_destination=stderr"
            ;;
        esac
        # IMPORTANT: call the official entrypoint so initdb still runs on first boot
        exec docker-entrypoint.sh postgres $$EXTRA
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  auth-portal:
    image: ${AUTH_PORTAL_IMAGE:-auth-portal:hardened-local}
    build:
      context: ./auth-portal
      dockerfile: Dockerfile
    ports:
      - "8089:8080"
    environment:
      # App
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8089}
      APP_TIMEZONE: ${APP_TIMEZONE:-UTC}
      TZ: ${TZ:-UTC}
      TRUSTED_PROXY_CIDRS: ${TRUSTED_PROXY_CIDRS:-}
      SESSION_SECRET: ${SESSION_SECRET:?set-in-.env}
      SESSION_COOKIE_DOMAIN: ${SESSION_COOKIE_DOMAIN:?set-in-.env}
      DATA_KEY: ${DATA_KEY:?set-in-.env}
      LOGIN_EXTRA_LINK_URL: ${LOGIN_EXTRA_LINK_URL:-}
      LOGIN_EXTRA_LINK_TEXT: ${LOGIN_EXTRA_LINK_TEXT:-}
      UNAUTH_REQUEST_EMAIL: ${UNAUTH_REQUEST_EMAIL:-}
      UNAUTH_REQUEST_SUBJECT: ${UNAUTH_REQUEST_SUBJECT:-}
      FORCE_SECURE_COOKIE: ${FORCE_SECURE_COOKIE:-0}
      FORCE_HSTS: ${FORCE_HSTS:-0}
      MEDIA_SERVER: ${MEDIA_SERVER:-plex}
      MFA_ENABLE: ${MFA_ENABLE:-1}
      MFA_ENFORCE: ${MFA_ENFORCE:-0}
      MFA_ISSUER: ${MFA_ISSUER:-AuthPortal}
      OIDC_SIGNING_KEY_PATH: ${OIDC_SIGNING_KEY_PATH:-}
      OIDC_SIGNING_KEY: ${OIDC_SIGNING_KEY:-}
      OIDC_ISSUER: ${OIDC_ISSUER:-http://localhost:8089}
      LOG_LEVEL: ${LOG_LEVEL:-INFO}

      # Admin Config
      ADMIN_BOOTSTRAP_USERS: ${ADMIN_BOOTSTRAP_USERS:?set-in-.env}

      # DB
      DATABASE_URL: postgres://authportal:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/authportaldb?sslmode=disable

      # LDAP Sync
      LDAP_HOST: ${LDAP_HOST:-ldap://ldap.example.com:389}
      LDAP_ADMIN_DN: ${LDAP_ADMIN_DN:-cn=admin,dc=authportal,dc=local}
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:-}
      BASE_DN: ${BASE_DN:-ou=users,dc=authportal,dc=local}
      LDAP_STARTTLS: ${LDAP_STARTTLS:-false}
      LDAP_DELETE_STALE_ENTRIES: ${LDAP_DELETE_STALE_ENTRIES:-false}
      LDAP_SYNC_SCHEDULE_ENABLED: ${LDAP_SYNC_SCHEDULE_ENABLED:-false}
      LDAP_SYNC_SCHEDULE_FREQUENCY: ${LDAP_SYNC_SCHEDULE_FREQUENCY:-daily}
      LDAP_SYNC_SCHEDULE_TIME: ${LDAP_SYNC_SCHEDULE_TIME:-02:15}
      LDAP_SYNC_SCHEDULE_DAY: ${LDAP_SYNC_SCHEDULE_DAY:-sunday}

      # Plex
      PLEX_OWNER_TOKEN: ${PLEX_OWNER_TOKEN:-}
      PLEX_SERVER_MACHINE_ID: ${PLEX_SERVER_MACHINE_ID:-}
      PLEX_SERVER_NAME: ${PLEX_SERVER_NAME:-}
      
      # Jellyfin
      JELLYFIN_SERVER_URL: ${JELLYFIN_SERVER_URL:-http://localhost:8096}
      JELLYFIN_API_KEY: ${JELLYFIN_API_KEY:-}
      JELLYFIN_APP_NAME: ${JELLYFIN_APP_NAME:-AuthPortal}
      JELLYFIN_APP_VERSION: ${JELLYFIN_APP_VERSION:-2.0.5}

      # Emby
      EMBY_SERVER_URL: ${EMBY_SERVER_URL:-http://localhost:8096}
      EMBY_APP_NAME: ${EMBY_APP_NAME:-AuthPortal}
      EMBY_APP_VERSION: ${EMBY_APP_VERSION:-2.0.5}
      EMBY_API_KEY: ${EMBY_API_KEY:-}
      EMBY_OWNER_USERNAME: ${EMBY_OWNER_USERNAME:-}
      EMBY_OWNER_ID: ${EMBY_OWNER_ID:-}
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- --header='Host: 127.0.0.1' http://127.0.0.1:8080/healthz >/dev/null || exit 1"]
      interval: 30s
      timeout: 3s
      start_period: 20s
      retries: 3
    networks: [authnet]

volumes:
  pgdata:

networks:
  authnet:
```


3) **Run**
```bash
docker compose up -d --build
# Visit http://localhost:8089
```

If you plan to use LDAP Sync, point the LDAP environment variables at your existing LDAP implementation, then open `Admin -> LDAP Sync` in AuthPortal to save connection settings, run a manual sync, or enable the built-in scheduler.

## Configuration

- `APP_BASE_URL`  external URL users hit (drives redirects & cookie flags). Use HTTPS in production.
- `SESSION_COOKIE_DOMAIN`  domain scope for session + pending-MFA cookies (e.g., `auth.example.com`).
- `MEDIA_SERVER`  `plex`, `jellyfin`, or `emby`.
- `SESSION_SECRET`  HMAC secret for the session JWT cookie (required, 32+ random bytes; the service refuses to start if unset or using the legacy default).
- `DATA_KEY`  base64 32-byte key for sealing provider tokens at rest (required).
- `MFA_ENABLE` / `MFA_ENFORCE` / `MFA_ISSUER`  multi-factor toggles; see below.
- `FORCE_SECURE_COOKIE`  set to `1` to force `Secure` on cookies (behind TLS/ingress).
- `FORCE_HSTS`  set to `1` to always emit Strict-Transport-Security even if `APP_BASE_URL` is http (use when TLS terminates upstream).
- `APP_TIMEZONE`  IANA timezone (e.g., `America/New_York`) used for backup scheduling and admin timestamps; set `TZ` to the same value in Docker to keep the container clock aligned.
- `TRUSTED_PROXY_CIDRS`  comma-separated CIDR ranges of proxies allowed to supply `X-Forwarded-For`/`X-Real-IP`; leave empty to rely on `RemoteAddr`.
- `TRUSTED_REDIRECT_HOSTS`  optional comma/semicolon-separated host allow-list for absolute OIDC `redirect_uri` values; if unset, allowed hosts derive from each client's registered redirect URIs.
- `LOGIN_EXTRA_LINK_URL`  external URL on authorized page.
- `LOGIN_EXTRA_LINK_TEXT`  text for that authorized-page link.
- `UNAUTH_REQUEST_EMAIL`  email address for unauthorized page "Request Access" mailto.
- `UNAUTH_REQUEST_SUBJECT`  subject for the unauthorized-page mailto link.
- `BACKUP_DIR`  filesystem path inside the container for generated config backups (default `./backups` relative to the binary).
- `LDAP_DELETE_STALE_ENTRIES`  when set to `true`, scheduled or manual LDAP syncs may delete stale entries previously marked as AuthPortal-managed under the configured LDAP base DN.
- `LDAP_SYNC_SCHEDULE_ENABLED` / `LDAP_SYNC_SCHEDULE_FREQUENCY` / `LDAP_SYNC_SCHEDULE_TIME` / `LDAP_SYNC_SCHEDULE_DAY`  bootstrap defaults for the built-in LDAP scheduler; once saved in Admin, the persisted runtime config takes precedence.
- `LOG_LEVEL`  `DEBUG`, `INFO`, `WARN`, or `ERROR`.

### Admin Console & Config Store (new in v2.0.4)

- Reach the admin experience at `/admin` with a user provisioned via `ADMIN_BOOTSTRAP_USERS` (comma-separated `username:email` pairs evaluated at startup).
- Providers, Security, MFA, App Settings, and LDAP Sync settings now persist in Postgres as JSON documents. Edits go through `/api/admin/config/{section}` with optimistic concurrency (`version` field) and are tracked in `/api/admin/config/history/{section}`.
- Each save accepts an optional change reason and appends to the audit log. Use the Refresh button to pull the latest runtime config before editing if multiple admins are active.
- The OAuth tab in the admin console surfaces live client management (list/create/update/delete plus secret rotation) backed by the `/api/admin/oauth/*` endpoints.

### LDAP Sync (new in v2.0.5)

- The **LDAP Sync** tab under `/admin` manages LDAP host/bind/Base-DN settings, StartTLS, optional stale-entry deletion, manual sync runs, and the built-in scheduler.
- The `Test Connection` action validates connect, bind, Base DN existence, and Base DN creatability before you save or sync.
- Scheduled runs support `hourly`, `daily`, and `weekly` timing directly in the UI and are reflected in the `Next Scheduled Run` panel state.
- Recent sync history includes manual and scheduled runs with trigger source, timestamps, result status, entry counts, and summary/error output.
- LDAP sync config changes participate in the same config history / Recent Changes workflow as the other admin sections.

### Backups

- The **Backups** tab under `/admin` lets you export the current config documents on demand (`Run Backup`) or configure an automatic schedule (hourly/daily/weekly with retention and section filters).
- Backup files are JSON blobs stored under `BACKUP_DIR` (default `./backups` beside the binary) and include metadata such as author, timestamp, and which sections were captured.
- Scheduled backup settings now live in the config store (section `backups`), so your cadence, selected sections, and retention persist across container rebuilds and are auditable like other config updates.
- Each row in the table supports `Download`, `Restore`, and `Delete`. Restore immediately applies the captured config via the standard validation pipeline; deletion only affects the filesystem.
- The same functionality is exposed via the REST API (`/api/admin/backups*`); see [HTTP Routes](#http-routes) below for endpoint details.

### OAuth 2.1 / OIDC Authorization Server (new in v2.0.4)

- Discovery endpoint `/.well-known/openid-configuration` advertises JWKS (`/oidc/jwks.json`), authorize (`/oidc/authorize`), token (`/oidc/token`), and userinfo (`/oidc/userinfo`) URLs.
- `/oidc/authorize` implements the authorization-code grant with PKCE. User consent is recorded per client/scope, supports `prompt=consent`, and returns `consent_required` when `prompt=none` is requested without prior approval.
- If a portal session is missing, `/oidc/authorize` is resumed after login (and MFA when required) using a validated local `next` continuation.
- Client `redirect_uri` validation is exact-string against the registered redirect URI list (scheme/host/path/query must match exactly).
- OAuth error responses redirect back to valid absolute callback URLs (`http`/`https`) with standard `error` query parameters.
- `/oidc/token` handles `authorization_code` and `refresh_token` grants. Refresh tokens rotate on every use and are only issued when the `offline_access` scope is granted.
- `/oidc/userinfo` returns `sub`, `preferred_username`, and optional email claims based on granted scopes. ID tokens are RS256-signed and echo the incoming `nonce`.
- Provide signing material with `OIDC_SIGNING_KEY_PATH` (PEM on disk) or inline `OIDC_SIGNING_KEY`; override the advertised issuer with `OIDC_ISSUER` when running behind a reverse proxy.
- Register clients through the admin console (OAuth tab) or the REST API: `GET/POST /api/admin/oauth/clients`, `PUT/DELETE /api/admin/oauth/clients/{id}`, and `POST /api/admin/oauth/clients/{id}/rotate-secret`.

### Multi-factor authentication

- `MFA_ENABLE` controls whether users can enroll; leave it `1` when enforcing.
- `MFA_ENFORCE` forces every login to satisfy MFA once a user is enrolled (or immediately when set globally).
- `MFA_ISSUER` customises the label your authenticator app displays and the recovery code download header.
- Enrollment lives under `/mfa/enroll/*`; challenges use `/mfa/challenge` and `/mfa/challenge/verify`. Recovery codes rotate on each successful verify.

### Plex

- `PLEX_SERVER_MACHINE_ID`  preferred; exact machine identifier of your server.
- `PLEX_SERVER_NAME`  fallback if machine id not set.
- `PLEX_OWNER_TOKEN`  optional owner token. If configured, the owner account is always authorized (account id match).

### Jellyfin

- `JELLYFIN_SERVER_URL`  e.g., `http://<host>:8096`.
	If Jellyfin runs in Docker, use your host IP from the app containers perspective (not `localhost`).
- `JELLYFIN_API_KEY`  optional; enables stricter authorization checks (`IsDisabled` policy).
- `JELLYFIN_APP_NAME`, `JELLYFIN_APP_VERSION`  client headers used in requests.

### Emby

- `EMBY_SERVER_URL`  e.g., `http://<host>:8096`.
	If Emby runs in Docker, use your host IP from the app containers perspective (not `localhost`).
- `EMBY_API_KEY`  optional; enables stricter authorization checks (`IsDisabled` policy).
- `EMBY_APP_NAME`, `EMBY_APP_VERSION`  client headers used in requests.

---

## Providers (Plex / Jellyfin / Emby)

- **Plex**:
`StartWeb` creates a PIN and returns the Plex Auth URL  popup opens.
`Forward` polls the PIN, fetches user info, seals token, decides authorization:
   1. User token can see configured server in `/api/v2/resources` (match machine id or name), OR
   2. Owner fallback if `PLEX_OWNER_TOKEN` is set and account ids match.

- **Jellyfin**:
`StartWeb` returns `/auth/forward?jellyfin=1`.
`Forward` (GET) serves a small login page; (POST) authenticates, seals token, validates the user token (`/Users/Me`), then (optionally) overlays admin policy via `JELLYFIN_API_KEY` (`IsDisabled`).

- **Emby**:
`StartWeb` returns `/auth/forward?emby=1`.
`Forward` (GET) serves a small login page; (POST) authenticates, seals token, and optionally checks `IsDisabled` via `EMBY_API_KEY`.

All providers implement `IsAuthorized(uuid, username)`; success is cached in `media_access`.

---

## Security Notes

- Token sealing: tokens are encrypted with `DATA_KEY` before DB insert/update. Unseal on read; failures clear the in-memory token.
- Cookies: Session and pending-MFA cookies honour `SESSION_COOKIE_DOMAIN`; they are HTTP-only, SameSite=Lax, and rotate after successful MFA. `Secure` is automatic when `APP_BASE_URL` is HTTPS, or force it with `FORCE_SECURE_COOKIE=1`.
- Rate limits: login endpoints share a per-IP limiter (burst 5, ~10 req/min); MFA enrollment/challenge use a tighter burst 3, ~5 req/min (tune in `main.go`).
- CSRF-lite: POST routes require same-origin via Origin/Referer.
- Headers:
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.
  Adds `Strict-Transport-Security: max-age=86400; includeSubDomains; preload` when `APP_BASE_URL` is HTTPS.
  Popup pages set a narrowed CSP that allows the tiny inline closing script.

---

## Database

### Users table (legacy-compatible):
```sql
id 			 BIGSERIAL PRIMARY KEY,
username     TEXT UNIQUE NOT NULL,
email        TEXT NULL,
media_uuid   TEXT UNIQUE,
media_token  TEXT NULL,
media_access BOOLEAN NOT NULL DEFAULT FALSE,
created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
```
### Indexes:
```sql
CREATE INDEX IF NOT EXISTS idx_users_username    ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_media_uuid  ON users (media_uuid);
```
### Plex PINs table (unchanged):
```sql
CREATE TABLE IF NOT EXISTS pins (
  code       TEXT PRIMARY KEY,
  pin_id     INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Identities

- Purpose: multi-provider identity linking (one row per provider per user).
- Columns: `user_id (FK)`, `provider`, `media_uuid`, `media_token`, `media_access`, timestamps.
- Uniqueness: `(provider, media_uuid)`, `(user_id, provider)`.
- Backfill: on startup, rows are inserted from `users.media_uuid` when present.
- Writes: app upserts into both `users` and `identities` (transition-friendly).
- Reads: prefer `identities` then fallback to `users` where needed.

---

## Build & Images

- Go: `1.26.1` on `alpine:3.23` (builder stage).
- Builder installs `git` + CA certs, runs `go mod download` then `go mod tidy -compat=1.26`, builds with:
    - `-v -x` (verbose), `-buildvcs=false` (avoid VCS scans), `-trimpath`, `-ldflags "-s -w"`.
- Runtime: `dhi.io/alpine-base:3.23-alpine3.23-dev`, installs CA certs + tzdata, runs as non-root `uid 10001`.

---

## Logging

- **App**: `LOG_LEVEL=DEBUG|INFO|WARN|ERROR`.
  Examples:
```pgsql
DEBUG jellyfin/auth POST http://<server>/Users/AuthenticateByName?format=json
WARN  emby/auth HTTP 401 body="..."
DEBUG plex: resources match via machine id
```
- **Postgres**: `LOG_LEVEL` maps to server params:
  - `DEBUG`  `log_min_messages=debug1`, connection/disconnection logging on
  - `INFO`  `log_min_messages=info`
  - `WARN`  `log_min_messages=warning`
  - `ERROR`  `log_min_messages=error`

---

## HTTP Routes

- **Core portal**
  - `GET /`  login page (auto-redirects to `/home` if session present).
  - `GET /home`  renders authorized or unauthorized view based on `IsAuthorized`.
  - `GET /whoami`  JSON: normalized identity and session metadata.
  - `GET /me`  JSON `{ username, uuid }` when logged in.
  - `POST /logout`  clears cookies; same-origin required.
  - `GET /static/*`  static assets.

- **Authentication**
  - `POST /auth/start-web`  JSON `{ authUrl }` (per-IP rate limited).
    - Plex: returns the Plex auth URL for the PIN flow.
    - Jellyfin/Emby: returns `/auth/forward?jellyfin=1` or `/auth/forward?emby=1`.
  - `GET|POST /auth/forward`  popup finisher for all providers.
    - Plex: completes PIN polling and closes the popup.
    - Jellyfin/Emby: GET serves the form; POST authenticates and closes the popup.
  - `GET /auth/poll`  Plex PIN poller (rate limited, JSON `{ status }`).

- **Multi-factor authentication**
  - `GET /mfa/challenge`  HTML challenge page shown when MFA is required.
  - `POST /mfa/challenge/verify`  JSON `{ ok, redirect, recoveryUsed, remainingRecoveryCodes }`; accepts optional `next` for OIDC continuation and rotates the session cookie on success.
  - `GET /mfa/enroll`  HTML enrollment UI for authenticated users.
  - `GET /mfa/enroll/status`  JSON summary of enrollment state (enabled/pending timestamps, remaining recovery codes).
  - `POST /mfa/enroll/start`  JSON `{ ok, secret, otpauth, digits, period, drift, enforced, previouslyEnabled }` to seed authenticator apps.
  - `POST /mfa/enroll/verify`  JSON `{ ok, recoveryCodes }` confirming enrollment and returning fresh recovery codes.

- **OAuth 2.1 / OIDC**
  - `GET /.well-known/openid-configuration`  discovery document.
  - `GET /oidc/jwks.json`  JWKS for RS256 validation.
  - `GET /oidc/authorize`  authorization-code endpoint; if not authenticated, redirects to login and resumes via `next`.
  - `POST /oidc/authorize/decision`  consent form postback (`allow`/`deny`).
  - `POST /oidc/token`  token exchange for authorization code + refresh grants.
  - `GET /oidc/userinfo`  userinfo endpoint (bearer token required).

- **Admin console & APIs**
  - `GET /admin`  admin SPA for bootstrap/admin users.
  - `GET /api/admin/config`  returns the admin configuration bundle, including Providers, Security, MFA, App Settings, and LDAP Sync.
  - `PUT /api/admin/config/{section}`  update a configuration section with optimistic concurrency.
  - `GET /api/admin/config/history/{section}`  fetch prior revisions.
  - `GET /api/admin/ldap-sync`  fetch LDAP sync config, scheduler status, and recent runs.
  - `POST /api/admin/ldap-sync/test-connection`  validate LDAP connectivity and Base DN readiness using the submitted form values without saving them.
  - `POST /api/admin/ldap-sync/run`  trigger a manual LDAP sync run.
  - `GET /api/admin/oauth/clients`  list registered OAuth clients.
  - `POST /api/admin/oauth/clients`  create a new client.
  - `PUT /api/admin/oauth/clients/{id}`  update client metadata.
  - `DELETE /api/admin/oauth/clients/{id}`  delete a client.
  - `POST /api/admin/oauth/clients/{id}/rotate-secret`  rotate client secret and return the new value.
  - `GET /api/admin/backups`  return the current schedule metadata plus available backup files.
  - `POST /api/admin/backups`  create a manual backup for the selected sections.
  - `PUT /api/admin/backups/schedule`  update the automated backup schedule (frequency, sections, retention).
  - `GET /api/admin/backups/{name}`  download a specific backup file.
  - `DELETE /api/admin/backups/{name}`  remove a backup file from storage.
  - `POST /api/admin/backups/{name}/restore`  restore captured config sections from a saved backup.

- **Health & readiness**
  - `GET /healthz`  liveness check.
  - `GET /readyz`  readiness (DB connectivity).
  - `GET /startupz`  startup probe sharing the same checks as readiness.

---


## Frontend Bits

- **Styles**: `static/styles.css` (icons clamped to 22"22 inside the sign-in button)
- **Login script**: `static/login.js`
  - Opens a placeholder popup synchronously on click, then navigates it (prevents popup blockers).
  - Accepts `postMessage` types: `plex-auth`, `emby-auth`, `jellyfin-auth`, `auth-portal`.
  - If the popup is closed/blocked, falls back to full-page nav.
  - Binds via `id="auth-signin"` / `[data-auth-signin]` / `.auth-signin`

---

## How it works
*High-level*

1. User clicks **Sign in with Plex/Emby/Jellyfin**; frontend opens the provider popup.
   - If the user is already authenticated with the provider, the popup returns immediately.
2. Server completes provider-specific auth, seals/stores the media token, and decides authorization.
3. If MFA is required (enforcement on or the user has enabled it), the app issues a pending-MFA cookie and redirects to `/mfa/challenge`; otherwise it sends the user directly to `/home`.
4. If login originated from `/oidc/authorize`, AuthPortal preserves that request and resumes it after login; MFA challenge completion also resumes the same authorize URL.
5. The MFA challenge verifies a TOTP or recovery code, rotates the JWT, clears the pending cookie, and redirects to the validated continuation target (or `/home`).
6. Session cookie TTL defaults to 24h for authorized users and 5m for unauthorized; authorized user profiles are stored in Postgres.
7. The opener page updates based on authorization, showing the authorized or restricted home experience and optional extra links.

---


## Customization

- **Logo:** in `templates/login.html`, swap the inline SVG for your logo.  
- **Colors & button:** tweak in `static/styles.css` (`--brand` etc.).
- **Authorized / Unauthorized pages:** edit `templates/portal_authorized.html` and `templates/portal_unauthorized.html`

---

## Security best practices

- Put AuthPortal behind **HTTPS** (e.g., Caddy / NGINX / Traefik).
- Set strong `SESSION_SECRET` (startup now fails if it's missing/short), `DATA_KEY`, and DB credentials.
- OAuth client secrets are hashed with bcrypt before storage; rotate legacy secrets so they’re re-hashed and unusable if the DB or backups leak.
- Access and refresh tokens are stored as deterministic SHA-256 digests, so leaked database rows don’t expose bearer tokens (rotate outstanding tokens after upgrading).
- Config backups written to disk are encrypted with the same `DATA_KEY`, so keep that key secret and re-bootstrap older plaintext backups if needed.
- Admin flag changes immediately revoke outstanding sessions by bumping an internal session version; reissue cookies after any privilege change.
- Dont expose Postgres or LDAP externally unless necessary.
- Keep images and dependencies updated.
- Enforce MFA everywhere by setting MFA_ENABLE=1 and MFA_ENFORCE=1; the code already backstops MFA_ENABLE when enforcement is on (main.go:55-74).
- If the portal is only used for same-origin apps, switch to SESSION_SAMESITE=strict; the fallback logic keeps you safe when Secure cookies aren’t yet possible (main.go:379-407).
- Keep rate limits aligned with your threat model; newIPRateLimiter accepts tighter limits if you need to clamp brute force attempts (rate_limiter.go:10-74).

---

## Security scans and code analysis

Automated security checks run on this project:

- Syft SBOM + Grype: SBOM generated from the built image; Grype scans that SBOM.
- Gitleaks: secret scanning on every push/PR; local hook below to keep commits clean.
- GitHub CodeQL: static analysis for code-level vulnerabilities in every PR and on main.
- Trivy: container and dependency scans to catch OS and library CVEs in our images.
- Docker Scout: image-level vulnerability insights for each commit/tag, including base image and layer analysis.
- SonarQube Cloud: continuous code quality and security hotspot detection across the codebase.

If you spot an issue or have questions about these scans, please open an issue or reach out.

### Local secret scanning (pre-commit)

Run Gitleaks locally before pushing:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

## Contributing

Issues and PRs welcome:  
https://github.com/modom-ofn/auth-portal/issues

---

## License

GPL-3.0  https://opensource.org/license/lgpl-3-0


> [!IMPORTANT]
> **Use at your own risk.** This project leans on Vibe Coding practices - AI pair-programming, automated refactors, and rapid iteration. Treat releases as starting points - test, monitor, and adapt to your stack. AuthPortal remains an independent effort with no endorsement from Plex, Emby, or Jellyfin.

---

## Upgrade Guide (to v2.0.5)

1) Rebuild or pull `modomofn/auth-portal:v2.0.5` so you pick up the built-in LDAP Sync admin module and scheduler improvements.
2) If you previously used the standalone `ldap-sync` workflow, migrate that configuration into `Admin -> LDAP Sync` and stop relying on the external repo/service.
3) If your compose/docs still reference `ldap-seed` for `ou=users`, remove that dependency unless you intentionally seed extra LDAP structure outside AuthPortal-managed sync.
4) Review LDAP behavior before enabling stale deletion:
   - Leave `Delete stale AuthPortal-managed LDAP entries` off until at least one successful built-in sync has updated the entries you want AuthPortal to own.
   - Verify the bind account has permission to create entries under the configured Base DN.
5) Set `SESSION_COOKIE_DOMAIN` to the host you serve AuthPortal from (e.g., `auth.example.com`) so session + pending-MFA cookies survive redirect flows.
6) Decide on MFA posture:
   - Leave `MFA_ENABLE=1` to let users enroll.
   - Flip `MFA_ENFORCE=1` if everyone must pass MFA on login; keep `MFA_ENABLE=1` in that case.
7) Verify end-to-end:
   - Existing users can log in, enroll, and download recovery codes.
   - Enforced logins reach `/mfa/challenge` and succeed with both TOTP codes and a recovery code.
   - Repeated bad logins or code attempts return HTTP 429 from the per-IP rate limiters.
   - LDAP `Test Connection` passes, a manual LDAP sync succeeds, and scheduled runs appear in `Recent Sync Runs` when enabled.
