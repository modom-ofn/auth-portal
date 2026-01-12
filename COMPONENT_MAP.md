# UI Component Map (Current CSS -> React Targets)

Source of truth: `auth-portal/static/styles.css`

This map focuses on reusable UI elements requested (buttons, inputs, tables, modals, banners) and the CSS classes that define them.

## Buttons
- Primary auth CTA: `.auth-btn` (variants: `.auth-btn.compact`) used on login/MFA flows.
- Portal button: `.btn` (variants: `.btn.ghost`, `.btn.primary`); also used for links styled as buttons.
- Ghost button (admin/tooling): `.ghost-btn` (also shares `.btn.ghost` styles).
- Primary admin action: `.primary-btn` (same styling as `.btn.primary`).
- Danger action: `.danger-btn` (used for destructive operations).
- Icon button: `.icon-btn` (compact circular icon button, e.g., help/close).
- Admin navigation tab: `.admin-tab` (with `.admin-tab.active` for selected state).
- Table sort button: `.sort-btn` (with `.sort-btn[data-sort-active="true"]` state).
- User name button: `.user-name-btn` (inline text button in tables).
- CTA brand button (optional): `.plex-btn` (Plex-styled CTA).

## Inputs (text, textarea, select)
- Shared input field: `.input` (base form input style).
- JSON editor textarea: `#config-editor`.
- OAuth form fields: `.oauth-form input`, `.oauth-form textarea`.
- Role form fields: `.role-form .form-row input`, `.role-form .form-row textarea`.
- Admin action input: `.admin-actions input`.
- User search: `#users-search`.
- Audit search: `#audit-search`.
- Backup schedule inputs/selects: `.backup-schedule-row input`, `.backup-schedule-row select`.

## Tables
- Users table: `.users-table` (wrapper: `.users-table-wrapper`).
- Audit table: `.audit-table` (wrapper: `.audit-table-wrapper`).
- OAuth clients table: `.oauth-table` (wrapper: `.oauth-table-wrapper`).
- Backup history table: `.backup-table` (wrapper: `.backup-table-wrapper`).
- Common table utilities: `.actions-cell`, `.actions-col` (right-aligned action column).

## Modals
- Modal container: `.modal` (hidden state: `.modal[hidden]`).
- Modal overlay: `.modal-backdrop`.
- Modal dialog: `.modal-dialog`.
- Modal body scroll area: `.modal-body`.
- Modal close button: `.close-btn` (used with `.icon-btn` styles in templates).
- Modal action section: `.user-info-actions`.

## Banners / Notices
- Status banner: `.status-banner` (states: `.status-banner.info`, `.status-banner.success`, `.status-banner.error`, `.status-banner.show`).
- Secret banner (admin config warning): `.secret-banner` (state: `.secret-banner.show`).
- Consent note (callout): `.consent-note`.
- Inline error notice (MFA): `.mfa-error`.
