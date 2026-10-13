# OIDC login continuation and cancellation


An OIDC sign-in carries a local `/oidc/authorize?...` continuation. The page retains
it per tab and offers Cancel. Plex opens a popup only from a click; blocked popups
allow retry. Polling/MFA continuation is retained, and cancelled/closed flows suppress
late completion. Emby/Jellyfin flows also expose cancellation and clean up popup timers.

`POST /oidc/login/cancel` accepts form field `next`. It validates a local authorize
continuation, client registration and the exact registered callback before returning
JSON `{"redirect":"..."}` with `error=access_denied`, the original `state`, and no
code. Same-origin checks apply; no authenticated session is required to cancel an
unfinished login. Downstream applications may display their ordinary OAuth error
page. Application-specific friendly-error proxy redirects are outside this branch.

Validation: Go callback tests and `node auth-portal/tests/login_flow_test.cjs auth-portal/static/login.js`; existing upstream tests retained.
