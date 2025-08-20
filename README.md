# AuthPortal

[![Docker Pulls](https://img.shields.io/docker/pulls/modomofn/auth-portal.svg)](https://hub.docker.com/r/modomofn/auth-portal)
[![Docker Image Size](https://img.shields.io/docker/image-size/modomofn/auth-portal/latest)](https://hub.docker.com/r/modomofn/auth-portal)
[![Go Version](https://img.shields.io/badge/Go-1.23.10%2B-00ADD8?logo=go)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL3.0-green.svg)](https://github.com/modom-ofn/auth-portal?tab=GPL-3.0-1-ov-file#readme)

**AuthPortal** is a lightweight, self-hosted authentication gateway for Plex users.
It reproduces Overseerr’s clean popup login (no code entry), stores the Plex token, and issues a secure session cookie for your intranet portal. It now differentiates between:

- ✅ Authorized Plex users → directed to the authorized home page.
- 🚫 Unauthorized Plex users → shown the restricted home page.

It can optionally be expanded to include LDAP integration for downstream app requirements.

👉 Docker Hub: https://hub.docker.com/r/modomofn/auth-portal
👉 GitHub Repo: https://github.com/modom-ofn/auth-portal

<img width="1147" height="804" alt="auth-portal-login" src="https://github.com/user-attachments/assets/69c8ebad-fd1a-4433-afed-6e929db8b354" />

<img width="642" height="838" alt="auth-portal-signin" src="https://github.com/user-attachments/assets/368f2370-dba3-4a82-b328-e501d4356708" />

<img width="649" height="393" alt="plex-authorized-portal" src="https://github.com/user-attachments/assets/b720766b-49ee-41d9-b223-d6d8bf3e615c" />

<img width="654" height="386" alt="plex-unauthorized-portal" src="https://github.com/user-attachments/assets/4cec68b5-b543-4590-9258-75072d28fb16" />

---

## ✨ Features

- 🔐 **Plex popup login** (no `plex.tv/link` code entry)
- 🎨 Overseerr-style dark UI with gradient hero and branded button
- 🍪 Signed, HTTP-only session cookie
- 🐳 Single binary, fully containerized
- ⚙️ Simple env-based config
- 🏠 Two distinct home pages: authorized vs. unauthorized

---

## 🚀 Deploy with Docker Compose


### **Docker Compose Minimal** (recommended for most users)
Use the following docker compose for a minimal setup (just postgres + auth-portal). This keeps only what AuthPortal truly needs exposed: port 8089. Postgres is internal.

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:15
    restart: unless-stopped
    environment:
      POSTGRES_DB: AuthPortaldb
      POSTGRES_USER: AuthPortal
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set-in-.env}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10

  auth-portal:
    image: modomofn/auth-portal:latest
    ports:
      - "8089:8080"
    environment:
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8089}
      SESSION_SECRET: ${SESSION_SECRET:?set-in-.env}
      DATABASE_URL: postgres://AuthPortal:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/AuthPortaldb?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

volumes:
  pgdata:
```
Create a .env next to it:
```txt
# .env
POSTGRES_PASSWORD=change-me-long-random
SESSION_SECRET=change-me-32+chars-random
APP_BASE_URL=http://localhost:8089
PLEX_OWNER_TOKEN=plxxxxxxxxxxxxxxxxxxxx
PLEX_SERVER_MACHINE_ID=abcd1234ef5678901234567890abcdef12345678
PLEX_SERVER_NAME=My-Plex-Server
```
Then:
```bash
docker compose up -d
```
**Open:** http://localhost:8089



### **Docker Compose Full Stack **
Use the following docker compose for a full stack setup (postgres, auth-portal, openldap, ldap-sync, phpldapadmin). Adds OpenLDAP, sync job, and phpLDAPadmin for downstream LDAP clients.

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:15
    restart: unless-stopped
    environment:
      POSTGRES_DB: AuthPortaldb
      POSTGRES_USER: AuthPortal
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set-in-.env}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  auth-portal:
    image: modomofn/auth-portal:latest
    ports:
      - "8089:8080"
    environment:
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8089}
      SESSION_SECRET: ${SESSION_SECRET:?set-in-.env}
      DATABASE_URL: postgres://AuthPortal:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/AuthPortaldb?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    networks: [authnet]

  openldap:
    image: osixia/openldap:1.5.0
    profiles: ["ldap"]
    environment:
      LDAP_ORGANISATION: AuthPortal
      LDAP_DOMAIN: AuthPortal.local
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:?set-in-.env}
    # Expose only if you need external LDAP clients:
    # ports:
    #   - "389:389"
    #   - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d
      # Seed OU/users if you like:
      # - ./ldap-seed:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro
    restart: unless-stopped
    healthcheck:
      # Use service DNS name inside the network, not localhost
      test: ["CMD-SHELL", "ldapsearch -x -H ldap://openldap -D 'cn=admin,dc=AuthPortal,dc=local' -w \"$LDAP_ADMIN_PASSWORD\" -b 'dc=AuthPortal,dc=local' -s base dn >/dev/null 2>&1"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  ldap-sync:
    build: ./ldap-sync
    profiles: ["ldap"]
    depends_on:
      postgres:
        condition: service_healthy
      openldap:
        condition: service_healthy
    environment:
      LDAP_HOST: openldap:389
      LDAP_ADMIN_DN: cn=admin,dc=AuthPortal,dc=local
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:?set-in-.env}
      BASE_DN: ou=users,dc=AuthPortal,dc=local
      DATABASE_URL: postgres://AuthPortal:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/AuthPortaldb?sslmode=disable
    restart: "no"
    networks: [authnet]

  phpldapadmin:
    image: osixia/phpldapadmin:0.9.0
    profiles: ["ldap"]
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: openldap
      PHPLDAPADMIN_HTTPS: "false"
    ports:
      - "8087:80"   # Only expose when you need to inspect LDAP
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
Create a .env next to it:
```txt
# .env
POSTGRES_PASSWORD=change-me-long-random
SESSION_SECRET=change-me-32+chars-random
APP_BASE_URL=http://localhost:8089
LDAP_ADMIN_PASSWORD=change-me-strong
PLEX_OWNER_TOKEN=plxxxxxxxxxxxxxxxxxxxx
PLEX_SERVER_MACHINE_ID=abcd1234ef5678901234567890abcdef12345678
PLEX_SERVER_NAME=My-Plex-Server
	# If both PLEX_SERVER_MACHINE & PLEX_SERVER_NAME are set, MACHINE_ID wins.
```
Run core only:
```bash
docker compose up -d
```
Run with LDAP stack:
```bash
docker compose --profile ldap up -d
```
**Open:** http://localhost:8089

---

## ⚙️ Configuration

| Variable                 | Required | Default                     | Description                                                                            |
|--------------------------|---------:|-----------------------------|----------------------------------------------------------------------------------------|
| `APP_BASE_URL`           |    ✅    | `http://localhost:8089`     | Public URL of this service. If using HTTPS, cookies will be marked `Secure`.           |
| `SESSION_SECRET`         |    ✅    | _(none)_                    | Long random string for signing the session cookie (HS256).                             |
| `PLEX_OWNER_TOKEN`       |    ✅    | _(none)_                    | Token from Plex server owner; used to validate server membership.                      |
| `PLEX_SERVER_MACHINE_ID` |    ✅    | _(none)_                    | Machine ID of your Plex server (preferred over name).                                  |
| `PLEX_SERVER_NAME`       |    ⛔    | _(none)_                    | Optional: Plex server name (used if machine ID not set).                               |

> Use a **long, random** `SESSION_SECRET` in production. Example generator: https://www.random.org/strings/

---

## 🧩 How it works (high level)

1. User clicks **Sign in with Plex** → JS opens `https://app.plex.tv/auth#?...` in a popup.  
2. Plex redirects back to your app at `/auth/forward` inside the popup.  
3. Server exchanges PIN → gets Plex profile → checks if user is authorized on your Plex server.  
4. Stores profile in DB, issues signed cookie.
5. Popup closes; opener navigates to:
- `/home` → Authorized
- `/restricted` → logged in, but not authorized

---

## 🖼️ Customization

- **Hero background:** put your image at `static/bg.jpg` (1920×1080 works great).  
- **Logo:** in `templates/login.html`, swap the inline SVG for your logo.  
- **Colors & button:** tweak in `static/styles.css` (`--brand` etc.).  
- **Footer:** customizable “Powered by Plex” in `templates/*.html`.
- **Authorized / unauthorized pages:** edit `templates/portal_authorized.html` and `templates/portal_unauthorized.html`

---

## 🧑‍💻 Local development

```bash
go run .

# visit http://localhost:8080
```

With Docker Compose:
```bash
docker compose up -dark
# visit http://localhost:8089
```

---

## 🔒 Security best practices

- Put AuthPortal behind **HTTPS** (e.g., Caddy / NGINX / Traefik).
- Set strong `SESSION_SECRET` and DB credentials.
- Don’t expose Postgres or LDAP externally unless necessary.
- Keep images updated.

---

## 📂 Project structure

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
│   ├── db.go
│   ├── Dockerfile
│   ├── go.mod
│   ├── handlers.go
│   ├── main.go
│   ├── LICENSE
│   ├── README.md
│   ├── templates/
│   	├── login.html
│   	├── portal_authorized.html
│   	└── portal_unauthorized.html
│   ├── static/
│   	├── styles.css
│   	├── login.js
│   	├── login.svg     # optional login button svg icon
│   	└── bg.jpg        # optional hero image
├── LICENSE
└── README.md
```

---

## 🧑‍💻 Items in the backlog

- ✅ (8/19/2025) Add container image to docker hub
- ✅ (8/19/2025) Security Hardening
- Authentication flow robustness
- App & backend reliability
- Database & data management improvements
- Container & runtime hardening
- UX polish
- LDAP / directory optimization
- Scale & deploy optimization

---

## 🤝 Contributing

Issues and PRs welcome:  
https://github.com/modom-ofn/auth-portal/issues

---

## 📜 License

GPL-3.0 — https://opensource.org/license/lgpl-3-0
