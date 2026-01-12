# Admin React Boundaries (Phase 1)

Source of truth: `auth-portal/templates/admin.html`, `auth-portal/static/admin.js`, `auth-portal/main.go`

## Routes
- React scope is only `/admin` (single page).
- Other pages remain server-rendered: `/`, `/login`, `/mfa`, `/oidc`, portal pages.

## Mount element
- Mount point: add a single root container (e.g., `<div id="admin-root"></div>`) in `auth-portal/templates/admin.html`.
- React owns all UI inside `/admin`; existing server-rendered admin HTML becomes the shell or is replaced by the mount container.

## Asset loading strategy
- Keep `auth-portal/static/styles.css` for shared styles.
- Replace `/static/admin.js` with a React bundle (e.g., `/static/admin-react.js`) loaded via `<script defer>` in `auth-portal/templates/admin.html`.
- Optional: emit `admin-react.css` if the build extracts CSS; otherwise keep styling in `styles.css`.

## Data fetching and auth assumptions
- Auth: requests use cookies with `credentials: "same-origin"`; `/admin` is protected via `adminGuard(permAdminAccess)` in `auth-portal/main.go`.
- APIs are all under `/api/admin/*` (same-origin; no additional auth headers).

### Config
- `GET /api/admin/config`
- `PUT /api/admin/config/{section}`
- `GET /api/admin/config/history/{section}?limit=25`
- `PUT /api/admin/config/ldap`

### Audit
- `GET /api/admin/audit?limit=100`

### Users and roles
- `GET /api/admin/users`
- `DELETE /api/admin/users/{id}`
- `DELETE /api/admin/users/unauthorized`
- `POST /api/admin/users/{id}/roles`
- `GET /api/admin/roles`
- `POST /api/admin/roles`
- `PUT /api/admin/roles/{name}`
- `DELETE /api/admin/roles/{name}`

### OAuth
- `GET /api/admin/oauth/clients`
- `POST /api/admin/oauth/clients`
- `PUT /api/admin/oauth/clients/{clientId}`
- `DELETE /api/admin/oauth/clients/{clientId}`
- `POST /api/admin/oauth/clients/{clientId}/rotate-secret`

### Backups
- `GET /api/admin/backups`
- `POST /api/admin/backups`
- `PUT /api/admin/backups/schedule`
- `DELETE /api/admin/backups/{name}`
- `POST /api/admin/backups/{name}/restore`
- `GET /api/admin/backups/{name}` (download)

### LDAP
- `GET /api/admin/ldap/status`
- `POST /api/admin/ldap/sync`

