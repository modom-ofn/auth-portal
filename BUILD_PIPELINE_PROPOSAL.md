# Minimal Build Pipeline Proposal (React Admin)

Goal: align on tooling and asset flow before coding.

## Build tool + output path
- Tooling: Vite (or similar, e.g., esbuild/Rollup).
- Output directory: `auth-portal/static/react/`.
- Output files are versioned with hashes (e.g., `admin.[hash].js`, `admin.[hash].css`).

## Asset loading (templates)
- `auth-portal/templates/admin.html` loads hashed assets directly:
  - `<link rel="stylesheet" href="/static/react/admin.[hash].css">` (if emitted)
  - `<script src="/static/react/admin.[hash].js" defer></script>`
- Maintain a small build manifest (e.g., `auth-portal/static/react/manifest.json`) to map logical names to hashed filenames.
- Template update strategy:
  - Option A: Server renders with the manifest (preferred long term).
  - Option B: Manual update of filenames until a manifest helper is added.

## CSS extraction + CSP compatibility
- CSS can remain in `auth-portal/static/styles.css` or be emitted as `admin.[hash].css`.
- CSP-safe because:
  - No inline `<script>` or `<style>` blocks.
  - Scripts and styles are external and same-origin (`script-src 'self'`).
  - No dynamic script injection is required.

## Build & asset flow (summary)
- Build React into hashed assets.
- Serve assets from `auth-portal/static/react/`.
- Load JS in `admin.html` with `<script src="/static/react/admin.[hash].js" defer></script>`.
- Load CSS via `<link rel="stylesheet" href="/static/react/admin.[hash].css">` if emitted.

## Implementation sketch (high level)
- Add a frontend workspace (e.g., `frontend/`) with Vite.
- Configure output path: `auth-portal/static/react/`.
- Generate a manifest for hashed assets.
- Update `auth-portal/templates/admin.html` to include the hashed CSS/JS.
- Confirm `main.go` continues to serve `/static/*` (already in place).

