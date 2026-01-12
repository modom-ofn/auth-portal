# CSP Compliance Checklist (Frontend Changes)

Goal: keep `script-src 'self'` intact while adding/adjusting frontend behavior.

## CSP source (current headers)
- Global CSP header in `auth-portal/main.go` (Content-Security-Policy).
- Provider HTML response CSP in `auth-portal/providers/provider.go` (Content-Security-Policy).

## Checklist (must pass)
- [ ] No inline `<script>` tags or inline event handlers (`onclick=`, `onload=`, etc).
- [ ] No inline `<style>` blocks or `style=` attributes. Use CSS files instead.
- [ ] All scripts are loaded from same-origin paths under `/static` (no third-party script origins).
- [ ] No `eval`, `new Function`, `setTimeout(string)`, or `setInterval(string)`.
- [ ] No dynamic script injection (`document.createElement('script')`, `innerHTML` script tags, or `import()` from external origins).
- [ ] Any new images/fonts/media load from allowed origins only (default is `'self'`; `img-src` currently allows `data:` and specific hosts).
- [ ] No changes that require `unsafe-inline` or `unsafe-eval` in `script-src`.

## Notes
- `script-src` currently allows only `'self'`, so any new JS must be served from this app.
- `style-src` currently allows `'unsafe-inline'`, but this checklist forbids inline styles for new work to avoid expanding CSP scope.

