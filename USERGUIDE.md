# AuthPortal User Guide

This document is the home for all how-to guides for users and admins.

## Admin How-Tos

### Create a custom role and assign it to users

1) Open `/admin` and go to the Roles section.
2) Enter a role name (lowercase, unique), description (optional), and one or more permissions.
3) Click **Create Role**.
4) In the Users table, open a user and toggle the custom role on.

Notes:
- AuthPortal ships with two built-in roles: `admin` and `user`.
- Only authorized users can be assigned custom roles. Guests are never written to LDAP.

### Use custom roles with LDAP for downstream apps

1) Create a custom role and assign it to authorized users (see above).
2) In the LDAP section of `/admin`, add mappings in the form:
   - `groupCn: role`
   - Example: `analytics-viewers: reports:read`
3) Save LDAP settings and run a sync (manual or auto).
4) Your downstream app reads LDAP group membership to authorize users.

How it works:
- AuthPortal syncs user entries to LDAP and writes group membership based on role-to-group mappings.
- If a mapped role has zero members, AuthPortal removes the group to avoid stale memberships.

### Use custom roles with OAuth/OIDC for downstream apps

AuthPortal's OAuth/OIDC server currently issues standard identity claims only:
- `sub`, `preferred_username`, and optional `email`
- Scopes: `openid`, `profile`, `email`, `offline_access`

Custom roles and permissions are not included in ID tokens, access tokens, or userinfo responses in v2.0.4. If a downstream app needs role-based authorization, use LDAP group mappings.

## User How-Tos

### Sign in and complete MFA

1) Sign in via the provider buttons on the login page.
2) If MFA is required, complete the challenge at `/mfa/challenge`.
3) If prompted, enroll MFA at `/mfa/enroll`.

