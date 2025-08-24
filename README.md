# AuthPortal (v2.0.0)

[![Docker Pulls](https://img.shields.io/docker/pulls/modomofn/auth-portal.svg)](https://hub.docker.com/r/modomofn/auth-portal)
[![Docker Image Size](https://img.shields.io/docker/image-size/modomofn/auth-portal/latest)](https://hub.docker.com/r/modomofn/auth-portal)
[![Go Version](https://img.shields.io/badge/Go-1.23.10%2B-00ADD8?logo=go)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL3.0-green.svg)](https://github.com/modom-ofn/auth-portal?tab=GPL-3.0-1-ov-file#readme)

**AuthPortal** is a lightweight, self-hosted authentication gateway for Plex, Jellyfin, or Emby.
It reproduces Overseerr’s clean popup login (no code entry), stores a sealed media-server token, and issues a secure session cookie for your intranet portal.

- ✅ Authorized Media Server users → directed to the authorized home page.
- 🚫 Unauthorized Media Server users → shown the restricted home page.

**“Use at your own risk. This project uses Vibe Coding and AI-Assitance. This project is unaffiliated with Plex, Inc. or Emby LLC. or Jellyfin”.**

It can optionally be expanded to include LDAP integration for downstream app requirements.

👉 Docker Hub: https://hub.docker.com/r/modomofn/auth-portal
👉 GitHub Repo: https://github.com/modom-ofn/auth-portal

---

## ✨ Features

- 🔐 **Popup login** (Plex PIN, Emby/Jellyfin username+password in a small popup form)
- 🎨 Overseerr-style dark UI with branded button (Plex/Emby/Jellyfin)
- 🍪 Signed, HTTP-only JWT session cookie
- 🐳 Single binary, fully containerized
- ⚙️ Simple env-based config
- 🏠 Two distinct home pages: authorized vs. unauthorized

---


---

## Table of Contents

- [What’s New in v2.0.0](#whats-new-in-v2.0.0)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Plex](#plex)
  - [Jellyfin](#jellyfin)
  - [Emby](#emby)
- [Providers (Plex / Jellyfin / Emby)](#providers-plex--jellyfin--emby)
- [Security Notes](#security-notes)
- [Database ](#database)
- [Build & Images](#build--images)
- [Logging](#logging)
- [HTTP Routes](#http-routes)
- [Frontend Bits](#frontend-bits)
- [How it works](#how-it-works)]
- [Customization](#customization)]
- [Security best practices](#security-best-practices)]
- [Project structure](#project-structure)]
- [Contributing](#contributing)]
- [License](#license)

---

## What’s New in v2.0.0

- **Media-agnostic user model**  
  DB columns renamed:
  - `plex_uuid → media_uuid`
  - `plex_token → media_token`
  - `plex_access → media_access`

- **Token sealing at rest**  
  Access tokens are encrypted (sealed) using `DATA_KEY` before persistence; unsealed only when needed.

- **Robust popup login flow**  
  Unified `static/login.js` supports **Plex** (PIN flow) and **Emby** (embedded popup form). Works with popup blockers by opening a placeholder synchronously.

- **Provider abstraction**  
  Common `MediaProvider` interface with `StartWeb`, `Forward`, and `IsAuthorized`.

- **Consistent styling/branding**  
  Emby popup page uses the existing `static/styles.css` and minimal inline spacing to match Plex look/feel.

- **Security hardening**  
  Global security headers; popup pages set a scoped CSP; optional HSTS when `APP_BASE_URL` is HTTPS.

- **Logout CSRF protection**  
  Same-origin check on POST `/logout`. Orphaned sessions no longer redirect-loop.

- **Configurable logging**  
  App and Postgres logging controlled via env (`LOG_LEVEL` / postgres flags).

---

## Quick Start

1) **.env**

```env
# ---------- Core ----------
POSTGRES_PASSWORD=change-me-long-random
SESSION_SECRET=change-me-32+chars-random
APP_BASE_URL=http://localhost:8089

# Authorized page extra link (optional)
LOGIN_EXTRA_LINK_URL=/some-internal-app
LOGIN_EXTRA_LINK_TEXT=Open Internal App

# Unauthorized page "Request Access" mailto link
UNAUTH_REQUEST_EMAIL=support@example.com
UNAUTH_REQUEST_SUBJECT=AuthPortal Access Request

# Set 'MEDIA_SERVER=' options: plex | emby (jellyfin later)
MEDIA_SERVER=plex

# Set 'FORCE_SECURE_COOKIE=1' in prod; if behind TLS/NGINX with X-Forwarded-Proto use 1
FORCE_SECURE_COOKIE=0

# 32-byte base64 key (e.g.,: openssl rand -base64 32)
DATA_KEY=5Z3UMPcF9BBkpB2SkuoXqYfGWKn1eXzpMdR8EyMV8dY=

# Logging # DEBUG | INFO | WARN | ERROR
LOG_LEVEL=DEBUG

# ---------- LDAP (only if using `--profile ldap`) ----------
LDAP_ADMIN_PASSWORD=change-me-strong

# ---------- Plex ----------
# Optional but recommended for server-authorization checks
PLEX_OWNER_TOKEN=plxxxxxxxxxxxxxxxxxxxx

# Either set machine id or a server name (machine id wins if both present)
PLEX_SERVER_MACHINE_ID=
PLEX_SERVER_NAME=

# ---------- Emby ----------
EMBY_SERVER_URL=http://localhost:8096
EMBY_APP_NAME=AuthPortal
EMBY_APP_VERSION=2.0.0
# EMBY_QUICKCONNECT=1  # (not yet implemented)
EMBY_API_KEY=
EMBY_OWNER_USERNAME=
EMBY_OWNER_ID=

# -------- JELLYFIN ---------
JELLYFIN_SERVER_URL=http://localhost:8096
JELLYFIN_API_KEY=
# optional JellyFin changes
JELLYFIN_APP_NAME=AuthPortal
JELLYFIN_APP_VERSION=2.0.0
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
        exec docker-entrypoint.sh postgres $EXTRA
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  auth-portal:
    image: modomofn/auth-portal:dev-r2
    ports:
      - "8089:8080"
    environment:
      # App
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8089}
      SESSION_SECRET: ${SESSION_SECRET:?set-in-.env}
      DATA_KEY: ${DATA_KEY:?set-in-.env}
      LOGIN_EXTRA_LINK_URL: ${LOGIN_EXTRA_LINK_URL:-}
      LOGIN_EXTRA_LINK_TEXT: ${LOGIN_EXTRA_LINK_TEXT:-}
      UNAUTH_REQUEST_EMAIL: ${UNAUTH_REQUEST_EMAIL:-}
      UNAUTH_REQUEST_SUBJECT: ${UNAUTH_REQUEST_SUBJECT:-}
      FORCE_SECURE_COOKIE: ${FORCE_SECURE_COOKIE:-0}
      MEDIA_SERVER: ${MEDIA_SERVER:-plex}
      LOG_LEVEL: ${LOG_LEVEL:-INFO}

      # DB
      DATABASE_URL: postgres://authportal:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/authportaldb?sslmode=disable

      # Plex
      PLEX_OWNER_TOKEN: ${PLEX_OWNER_TOKEN:-}
      PLEX_SERVER_MACHINE_ID: ${PLEX_SERVER_MACHINE_ID:-}
      PLEX_SERVER_NAME: ${PLEX_SERVER_NAME:-}
      
      # Jellyfin
      JELLYFIN_SERVER_URL: ${JELLYFIN_SERVER_URL:-http://localhost:8096}
      JELLYFIN_API_KEY: ${JELLYFIN_API_KEY:-}
      JELLYFIN_APP_NAME: ${JELLYFIN_APP_NAME:-AuthPortal}
      JELLYFIN_APP_VERSION: ${JELLYFIN_APP_VERSION:-2.0.0}

      # Emby (quick connect coming soon)
      EMBY_SERVER_URL: ${EMBY_SERVER_URL:-http://localhost:8096}
      EMBY_APP_NAME: ${EMBY_APP_NAME:-AuthPortal}
      EMBY_APP_VERSION: ${EMBY_APP_VERSION:-2.0.0}
      # EMBY_QUICKCONNECT: ${EMBY_QUICKCONNECT:-}
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

  openldap:
    image: osixia/openldap:1.5.0
    profiles: ["ldap"]
    environment:
      LDAP_ORGANISATION: AuthPortal
      LDAP_DOMAIN: authportal.local
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:?set-in-.env}
    # Uncomment if you need external LDAP access from host:
    # ports:
    #   - "389:389"
    #   - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d
      # Seed OU/users if desired:
      # - ./ldap-seed:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro
    restart: unless-stopped
    healthcheck:
      # Use service DNS name inside the network, not localhost
      test: ["CMD-SHELL", "ldapsearch -x -H ldap://openldap -D 'cn=admin,dc=authportal,dc=local' -w \"$LDAP_ADMIN_PASSWORD\" -b 'dc=authportal,dc=local' -s base dn >/dev/null 2>&1"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  ldap-sync:
    image: modomofn/ldap-sync:dev
    profiles: ["ldap"]
    depends_on:
      postgres:
        condition: service_healthy
      openldap:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://authportal:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/authportaldb?sslmode=disable
      LDAP_HOST: ldap://openldap:389
      LDAP_ADMIN_DN: cn=admin,dc=authportal,dc=local
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:?set-in-.env}
      BASE_DN: ou=users,dc=authportal,dc=local
      # LDAP_STARTTLS: "true"   # enable if your server supports StartTLS
    restart: "no"
    networks: [authnet]

  phpldapadmin:
    image: osixia/phpldapadmin:0.9.0
    profiles: ["ldap"]
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: openldap
      PHPLDAPADMIN_HTTPS: "false"
    ports:
      - "8087:80"
    depends_on:
      openldap:
        condition: service_healthy
    restart: unless-stopped
    networks: [authnet]

volumes:
  pgdata:
  ldap_data:
  ldap_config:

networks:
  authnet:
```

3) **Run**
```bash
docker compose up -d --build
# Visit http://localhost:8089
```

*Run with LDAP stack:*
```bash
docker compose --profile ldap up -d --build
# Visit http://localhost:8089
```

## Configuration

- `APP_BASE_URL` — external URL users hit (drives redirects & cookie flags). Use HTTPS in production.
- `MEDIA_SERVER` — `plex` or `jellyfin` or `emby`.
- `SESSION_SECRET` — HMAC secret for JWT cookie (required).
- `DATA_KEY` — base64 32-byte key for sealing tokens at rest (required).
- `LOG_LEVEL` — `DEBUG`, `INFO`, `WARN`, or `ERROR`.
- `FORCE_SECURE_COOKIE` — set to 1 to force Secure on cookies (behind TLS/ingress).
- `LOGIN_EXTRA_LINK_URL` — external URL on authorized page.
- `LOGIN_EXTRA_LINK_TEXT` — text for external URL on authorized page.
- `UNAUTH_REQUEST_EMAIL` — email address for unauthorized page request access link
- `UNAUTH_REQUEST_SUBJECT` — subject for unuathorized page request access email

### Plex

- `PLEX_SERVER_MACHINE_ID` — preferred; exact machine identifier of your server.
- `PLEX_SERVER_NAME` — fallback if machine id not set.
- `PLEX_OWNER_TOKEN` — optional owner token. If configured, the owner account is always authorized (account id match).

### Jellyfin

- `JELLYFIN_SERVER_URL` — e.g., `http://<host>:8096`.
	If Jellyfin runs in Docker, use your host IP from the app container’s perspective (not `localhost`).
- `JELLYFIN_API_KEY` — optional; enables stricter authorization checks (`IsDisabled` policy).
- `JELLYFIN_APP_NAME`, `JELLYFIN_APP_VERSION` — client headers used in requests.

### Emby

- `EMBY_SERVER_URL` — e.g., `http://<host>:8096`.
	If Emby runs in Docker, use your host IP from the app container’s perspective (not `localhost`).
- `EMBY_API_KEY` — optional; enables stricter authorization checks (`IsDisabled` policy).
- `EMBY_APP_NAME`, `EMBY_APP_VERSION` — client headers used in requests.

---

## Providers (Plex / Jelly Fin / Emby)

- **Plex**:
`StartWeb` creates a PIN and returns the Plex Auth URL → popup opens.
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
- Cookies: JWT in HTTP-only, SameSite=Lax cookie. `Secure` is enabled automatically when `APP_BASE_URL` is HTTPS, or force with `FORCE_SECURE_COOKIE=1`.
- CSRF-lite: POST routes require same-origin via Origin/Referer.
- Headers:
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
  Popup pages set a narrowed CSP that allows the tiny inline closing script.

---

## Database

### Users table (dev-r2):
```sql
id BIGSERIAL PRIMARY KEY,
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

---

## Build & Images

- Go: `1.23.10` on `alpine:3.21`.
- Builder installs `git` + CA certs, runs `go mod download` then `go mod tidy -compat=1.23`, builds with:
    - `-v -x` (verbose), `-buildvcs=false` (avoid VCS scans), `-trimpath`, `-ldflags "-s -w"`.
- Runtime: `alpine:3.21`, installs CA certs + tzdata, runs as non-root `uid 10001`.

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
  - `DEBUG` → `log_min_messages=debug1`, connection/disconnection logging on
  - `INFO` → `log_min_messages=info`
  - `WARN` → `log_min_messages=warning`
  - `ERROR` → `log_min_messages=error`

---

## HTTP Routes

- `GET /` — login page (auto-redirects to /home if session present)
- `POST /auth/start-web` — JSON `{ authUrl }`
	- Plex: returns Plex Auth URL (PIN flow)
	- Jellyfin/Emby: returns `/auth/forward?jellyfin=1` or `/auth/forward?emby=1`
- `GET|POST /auth/forward` — popup finisher
	- Plex: completes PIN polling, closes popup
	- Jellyfin: GET → form; POST → authenticate and close
	- Emby: GET → form; POST → authenticate and close
- `GET /me` — JSON: `{ username, uuid }` if logged in
- `GET /home` — renders Authorized / Unauthorized based on `IsAuthorized`
- `POST /logout` — clears cookie; same-origin required
- `GET /healthz` — health check
- `GET /statupz`, `GET /readyz` — readiness (DB)
- `GET /static/*` — static assets

---

## Frontend Bits

- **Styles**: `static/styles.css` (icons clamped to 22×22 inside the sign-in button)
- **Login script**: `static/login.js`
  - Opens a placeholder popup synchronously on click, then navigates it (prevents popup blockers).
  - Accepts `postMessage` types: `plex-auth`, `emby-auth`, `jellyfin-auth`, `auth-portal`.
  - If the popup is closed/blocked, falls back to full-page nav.
  - Binds via `id="auth-signin"` / `[data-auth-signin]` / `.auth-signin`

---

## How it works
*High-level*

1. User clicks **Sign in with Plex/Emby/Jellyfin** → JS opens auth flow in a popup.
    - If user is already logged on, redirect to home is automatic
2. Server completes provider-specific auth, seals/stores token, and decides authorization.  
4. Session cookie is set (24h default for authorized, 5m for unauthorized).  
5. Stores only authorized user's profile in DB
6. Issues signed cookies with variable TTL (5m for unauthorized, 24h for authorized)
7. Popup posts a success message to the opener and closes; opener goes to:
    - `/home` → Authorized
    - `/home` → logged in, but NOT authorized

---

## Customization

- **Hero background:** put your image at `static/bg.jpg` (1920×1080 works great).  
- **Logo:** in `templates/login.html`, swap the inline SVG for your logo.  
- **Colors & button:** tweak in `static/styles.css` (`--brand` etc.).
- **Authorized / Unauthorized pages:** edit `templates/portal_authorized.html` and `templates/portal_unauthorized.html`

---

## Security best practices

- Put AuthPortal behind **HTTPS** (e.g., Caddy / NGINX / Traefik).
- Set strong `SESSION_SECRET`, `DATA_KEY`, and DB credentials.
- Don’t expose Postgres or LDAP externally unless necessary.
- Keep images and dependencies updated.

---

## Project structure

```
.
├── ldap-seed/ # optional LDAP seed
│   └── 01-ou-users.ldif
├── ldap-sync/ # optional LDAP sync service
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go
├── auth-portal/
│   ├── context_helpers.go
│   ├── crypto.go
│   ├── crypto_tokens.go
│   ├── db.go
│   ├── Dockerfile
│   ├── go.mod
│   ├── handlers.go
│   ├── logging.go
│   ├── main.go
│   ├── providers.go
│   ├── store.go
│   ├── LICENSE
│   ├── README.md
│   ├── health/ # health check function
│   	├── health.go
│   ├── templates/
│   	├── login.html
│   	├── portal_authorized.html
│   	└── portal_unauthorized.html
│   ├── static/
│   	├── styles.css
│   	├── login.js
│   	├── login.svg     # optional login button svg icon
│   	├── plex.svg      # optional plex button svg icon
│   	├── emby.svg      # optional emby button svg icon
│   	├── jellyfin.svg  # optional jellyfin button svg icon
│   	└── bg.jpg        # optional hero image
├── auth-portal-full-stack-dev.env					# full stack docker-compose env template
├── auth-portal-full-stack-dev_docker-compose.yml	# full stack docker-compose template
├── LICENSE
└── README.md
```

---

##  Contributing

Issues and PRs welcome:  
https://github.com/modom-ofn/auth-portal/issues

---

##  License

GPL-3.0 — https://opensource.org/license/lgpl-3-0

**“Use at your own risk. This project uses Vibe Coding and AI-Assitance. This project is unaffiliated with Plex, Inc. or Emby LLC. or Jellyfin”.**
