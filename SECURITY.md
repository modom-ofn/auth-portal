# Security Policy

I take security seriously and want AuthPortal operators to feel confident running the latest release. This page explains which versions receive fixes and how to notify me when you spot a weakness.

## Supported Versions

Security fixes are provided for actively maintained release lines. Anything outside the windows below no longer receives updates—even for critical issues.

| Version line | Status | Notes |
| ------------ | ------ | ----- |
| `v2.0.x` (latest: `v2.0.3`) | ✅ Supported | Receives all security and high-priority bug fixes. |
| `dev` branch | ✅ Supported | Pre-release builds; fixes land here first and are promoted into the next tagged release. |
| `< v2.0.0` | ❌ End-of-life | Please upgrade to a supported release. |

When a new minor series ships, the previous series remains supported for at least 90 days. I will post deprecation notices in the release notes and CHANGELOG when a branch approaches end-of-life.

## Reporting a Vulnerability

I would prefer that you disclose vulnerabilities responsibly through **GitHub Issues** so I can track them openly while protecting sensitive details.

1. Open a new issue at https://github.com/modom-ofn/auth-portal/issues/new/choose and pick the *Security report* template (or the closest option available).  
2. Include:
   - The exact AuthPortal version (`VERSION` file or Docker tag) and deployment mode.  
   - Steps to reproduce or proof-of-concept payloads. Mask or redact secrets before posting.  
   - Impact assessment (what could an attacker achieve, what preconditions are required).  
   - Any suggested mitigations or workarounds you discovered.
3. Tag the issue with `security` if possible; if not, I will add it after triage.

### What to Expect

- **Acknowledgement:** I review new security issues as soon as possible.  
- **Triage:** If I need clarification, I will comment in the issue; please monitor notifications until the item is resolved.  
- **Resolution:** Confirmed vulnerabilities are patched on the `dev` branch and rolled into the next tagged release. I aim to publish fixes for high-severity bugs within 14 days.  
- **Advisories:** For issues that warrant an advisory or CVE, I will coordinate disclosure and provide upgrade guidance in the release notes and README.

If you believe the issue should remain private until a fix is available, mention that in the issue body. We can coordinate embargoed communication on a case-by-case basis.

Thank you for helping keep AuthPortal secure for everyone! Your reports make the project stronger.


## Additional Security Note

AuthPortal layers AES-GCM token sealing, HTTP-only JWT sessions, CSP/HSTS headers, MFA gating, per-IP rate limiting, CSRF origin checks, and encrypted config/backups to protect its authentication flows, but it is still “use at your own risk,” so you should treat these controls as best-effort hardening rather than formal assurance.

### Security Measures

- **Encrypted credentials:** media tokens are AES-256-GCM sealed before storage, OAuth client secrets are bcrypt-hashed, and config backups reuse the same DATA_KEY, reducing impact from DB or backup leaks.
- **Session hardening:** signed HTTP-only JWT cookies honor SESSION_COOKIE_DOMAIN, enforce SameSite defaults, optionally force Secure, and clear pending MFA cookies whenever sessions rotate.
- **Rate limits plus MFA:** shared per-IP limiters guard login/start-forward flows, separate limiters protect Plex polling/MFA endpoints, and enforced MFA can hold users at a pending cookie until codes succeed.
- **CSRF-lite controls:** every state-changing route (start-web, forward, MFA APIs, logout) passes through an Origin/Referer validator that builds an allowlist from APP_BASE_URL and proxy headers.
- **Security headers:** all responses carry X-Frame-Options, X-Content-Type-Options, Referrer-Policy, a restrictive CSP, and conditional Strict-Transport-Security (or forceable via FORCE_HSTS).
- **Config governance:** provider/security/MFA JSON lives in Postgres with optimistic versioning, in-browser history, scheduled backups, and download/restore flows for recovery.
- **Token privacy for OIDC:** access/refresh tokens are stored as deterministic SHA-256 digests, limiting exposure if databases or logs leak.
- **Runtime hygiene:** containers are built on Alpine with CA certs/tzdata only, and the final image runs as non-root UID 10001 to shrink the attack surface.