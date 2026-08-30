# Versioning and Release Policy

AuthPortal follows [Semantic Versioning 2.0.0](https://semver.org/). Git tags use
the conventional `v` prefix; the version itself does not.

## Compatibility surface

Version decisions account for documented HTTP, Admin, OAuth/OIDC, and health
APIs; environment variables and persisted configuration; RBAC permission names
and behavior; backup/import formats; supported database migrations; and
documented container/deployment interfaces.

- **Major** (`X.0.0`): an incompatible change to the compatibility surface.
- **Minor** (`X.Y.0`): backward-compatible functionality or deprecation.
- **Patch** (`X.Y.Z`): backward-compatible bug or security fixes only.

Supported prereleases are `X.Y.Z-alpha.N`, `X.Y.Z-beta.N`, and `X.Y.Z-rc.N`.
Build metadata is not used for release tags.

## Branches

- `main` is protected and represents the current stable line.
- `next` is the temporary protected integration branch for the next major
  release. Its container channel is `edge`.
- Short-lived `feat/*`, `fix/*`, `chore/*`, and `release/*` branches merge by
  pull request.
- Ordinary branches never publish stable packages or GitHub Releases.

Maintenance fixes target the current stable line and are merged forward into
`next` while the next major is in development.

## CI and publication

- Pull requests and pushes to `main` or `next` run CI without publishing a
  stable package.
- Pushes to `next` publish only `edge` and `sha-<commit>` container tags.
- Only a validated Git tag whose value exactly matches `VERSION` can publish a
  GitHub Release or versioned container tags.
- Stable tags publish `vX.Y.Z`, `vX.Y`, `vX`, and `latest`.
- Prerelease tags publish only their exact `vX.Y.Z-<stage>.N` tag.
- Candidate images are scanned by immutable digest before stable tags are
  promoted.

Release containers are published to both:

- `docker.io/modomofn/auth-portal`
- `ghcr.io/modom-ofn/auth-portal`

GitHub Releases include the SBOM, vulnerability reports, and checksums. Released
GHCR images receive provenance and SBOM attestations.

## Release sequence

1. Update `VERSION`, release notes, upgrade guidance, and any fallback display
   version in a short-lived `release/X.Y.Z` branch.
2. Merge the release pull request after all required checks pass.
3. Create the protected release tag on the exact merge commit.
4. The tag-only release workflow builds immutable candidates, scans their
   digest, promotes approved tags, uploads evidence, and publishes the GitHub
   Release.
5. Published tags and release assets are never moved or replaced. Corrections
   require a new version.
