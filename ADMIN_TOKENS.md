# Admin Tokens & Utilities (CSS Audit)

Source of truth: `auth-portal/static/styles.css`

## Design Tokens (Admin Pages)
Defined in `:root` and referenced across admin styles:
- `--bg`, `--bg2` (page backgrounds)
- `--card` (panel/card surface)
- `--muted` (secondary text)
- `--border` (borders, separators)
- `--text` (primary text)
- `--brand` (accent/CTA)
- `--ok`, `--warn` (status accents)
- `--space-1`..`--space-5` (spacing scale)
- `--radius-sm`, `--radius-md`, `--radius-lg` (corner radius scale)

## Layout Utilities (Structure)
- `.stack`, `.stack.sm`, `.stack.center` (vertical rhythm)
- `.cluster`, `.cluster.center` (inline grouping)
- `.center` (page centering)
- `.center-row` (row centering)
- `.text-center` (text alignment)
- `.mt-xs`, `.mt-sm`, `.mt-md`, `.spacer-sm` (spacing helpers)
- `.is-hidden` (visibility toggle)

## Admin-Specific Overrides / Exceptions
- Base admin page: `.admin-page` (background, text color, min-height).
- Admin layout shell: `.admin-header`, `.admin-main`, `.admin-nav`, `.admin-content`.
- Admin panels: `.panel`, `.panel-header`, `.panel-helper`, `.panel-header-actions`.
- Admin-only inputs: `#config-editor`, `.admin-actions input`, `#users-search`, `#audit-search`, `.backup-schedule-row input/select`.
- Admin-only tables: `.users-table`, `.audit-table`, `.oauth-table`, `.backup-table` and wrappers.
- Admin-only modals: `.modal`, `.modal-dialog`, `.modal-body`.
- Admin feedback: `.status-banner` (info/success/error), `.secret-banner` (config warnings).

