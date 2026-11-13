# Dependency and security audit - 2026-11-13

## Scope and baseline

- Branch: `chore/dependency-security-audit-2026-11-13`, created from fetched
  `origin/main` at `62fea17` (local main matched; working tree was clean).
- PRs #177 and #178 are excluded: do not continue, cherry-pick, or merge them.
- This section records the initial assessment. The implementation checkpoint
  below records subsequent authorized maintenance changes.
- Sources: Go module proxy, Go vulnerability database, upstream GitHub release
  APIs, Docker Hub tag API, and Docker Scout registry scans on this date.

## Priority recommendations

1. Update the Go toolchain, Docker builder, CI version, and current documentation
   from 1.26.8 to 1.26.11. Staying on the supported 1.26 line avoids an unnecessary
   minor-version migration. Latest stable overall is 1.27.4.
2. Refresh the pinned hardened runtime image: published v2.0.6 includes
   `musl 1.2.5-r23`, flagged for CVE-2026-107891 (fixed in `1.2.5-r24`).
   Package presence is not proof of exploitability; AuthPortal is built with
   `CGO_ENABLED=0`. Rebuild and scan both supported architectures.
3. Update `go-ldap` 3.4.14 to 3.4.15 and `x/crypto` 0.57.0 to 0.59.0.
   Both releases retain a Go 1.26 minimum. LDAP includes malformed-packet/filter
   handling fixes. The crypto update also clears the module-only OpenPGP finding.
4. Correct Dependabot's `gomod` directory from `/` to `/auth-portal` and add
   Docker dependency coverage. Add a source `govulncheck` CI check: current PR CI
   runs tests/vet/build but has no source vulnerability check.
5. Assess PostgreSQL 15.20 and refresh its digest after database compatibility
   and image checks. The current 15.19 digest has substantial package findings;
   changing only to 15.20-trixie does not resolve most of them.
6. Refresh CI actions and security tools with verified immutable pins/checksums;
   stage major action upgrades separately and validate their inputs/runtimes.

## Go vulnerability results

`govulncheck v1.9.0`, source scan on Windows amd64 using the declared Go 1.26.8:
14 symbol-reachable standard-library findings, one imported-but-not-called
finding, and one module-only finding. Static reachability is not an exploit
reproduction; deployment conditions still matter.

| Go advisory | CVE | Package/behavior | Fixed in |
| --- | --- | --- | --- |
| GO-2026-6599 | CVE-2026-94448 | html/template context tracking | 1.26.9 |
| GO-2026-6600 | CVE-2026-97030 | html/template regexp escaping | 1.26.9 |
| GO-2026-6603 | CVE-2026-78659 | HTTP/2 trailer memory exhaustion | 1.26.9 |
| GO-2026-6605 | CVE-2026-56866 | HTTP/1 client CONNECT desynchronization | 1.26.9 |
| GO-2026-6607 | CVE-2026-97031 | TLS malformed ECH references | 1.26.9 |
| GO-2026-6608 | CVE-2026-94440 | MIME header memory limits | 1.26.9 |
| GO-2026-6609 | CVE-2026-78667 | HTTP Range header size | 1.26.9 |
| GO-2026-6610 | CVE-2026-78660 | HTTP/2 framing headers | 1.26.9 |
| GO-2026-6611 | CVE-2026-78669 | HTTP/2 initial-window CPU consumption | 1.26.9 |
| GO-2026-6612 | CVE-2026-78663 | HTTP/2 flow-control refund | 1.26.9 |
| GO-2026-6613 | CVE-2026-94439 | HTTP/1 server CONNECT desynchronization | 1.26.9 |
| GO-2026-6617 | CVE-2026-97032 | HTTP/2 HPACK encoder race | 1.26.9 |
| GO-2026-6809 | CVE-2026-111943 | x509 compromised intermediates | 1.26.10 |
| GO-2026-6859 | CVE-2026-97054 | HTTP/1 MaxBytesReader race | 1.26.11 |

- GO-2026-6604 / CVE-2026-56857 (`os.Root` Windows junction escape) is in an
  imported package but has no called vulnerable symbol; fixed in 1.26.9.
- GO-2026-5932 concerns unused `x/crypto/openpgp`; the module is required, but
  that package is not imported. The database now lists a fix, unlike earlier
  assessments. Prefer stable x/crypto 0.59.0 over the listed pseudo-version.
- Running the unchanged source with `GOTOOLCHAIN=go1.26.11` produces **zero
  reachable findings**, zero imported-package findings, and only GO-2026-5932
  at module level. This does not update the production binary.

## Available module updates

Direct dependencies with updates: LDAP 3.4.15 and x/crypto 0.59.0. sqlmock,
jwt/v5, mux, lib/pq, and x/time are already at their latest module-proxy releases.

Other updates in the full module graph: hashicorp/go-uuid 1.0.4, sqlstruct
`v0.0.0-20260911144101-d2980d3f1271`, testify 1.12.1, x/net 0.62.0, x/sys
0.50.0, x/term 0.48.0, and x/text 0.44.0. These are not all direct runtime
dependencies. Let selected module upgrades and tidy resolve their requirements;
avoid adding every test/transitive module as a direct requirement.

## Registry image findings

Scout CLI 1.27.0, using registry attestations. Counts include package-presence
findings and are time-sensitive; they are not reachability-filtered.

| Image/platform | Critical | High | Medium | Low | Unspecified |
| --- | ---: | ---: | ---: | ---: | ---: |
| AuthPortal v2.0.6 amd64 | 2 | 10 | 3 | 0 | 2 |
| AuthPortal v2.0.6 arm64 | 2 | 10 | 3 | 0 | 2 |
| Pinned PostgreSQL 15.19 amd64 | 4 | 41 | 36 | 56 | 12 |
| Candidate PostgreSQL 15.20-trixie amd64 | 4 | 40 | 36 | 56 | 12 |

Resolved platform digests:

- AuthPortal amd64: `sha256:43fa7ad84ca03a51ecbe7b302a58c8fd0f520c43221661c9f06e331b869b685d`
- AuthPortal arm64: `sha256:ba70dd4d924bf2ca91d7c040e3264bc986437d482286b05678dae21805e3a06b`
- Pinned PostgreSQL amd64: `sha256:a5f9ead8ed7cb25abc36bea51fb9bb2be8d5579ed4ef3d28876027e438391ff0`
- Candidate PostgreSQL amd64: `sha256:8a7b3318a33b4c4b366d3ada884d5339d719114e837f0d43776835ff01dec927`

PostgreSQL's existing index pin is
`sha256:7e2070cf6ad06fb3cbbd141b1bafbb7fd5bb63e2b6001e6daf34448eb555e4b3`.
Candidate 15.20-trixie index:
`sha256:ad51f1a9aec85898aff1d1702ac361039286460de92d25610c85d76950f5d212`.
PostgreSQL findings include a Go 1.24.6 binary and OS packages; assess actual
components and use before attributing them to the database server.

## CI and scanner updates

Latest upstream releases observed; availability alone is not a security finding.

| Component | Repository setting | Available |
| --- | --- | --- |
| actions/checkout | 7.0.1 | 7.0.1 |
| actions/setup-go | 6 | 7.0.0 |
| actions/setup-node | 6 | 7.1.0 |
| actions/attest | 4 | 4.2.2 |
| actions/upload-artifact | 7.0.0 | 7.0.2 |
| docker/setup-qemu-action | 4.2.0 | 4.4.0 |
| docker/setup-buildx-action | 4.2.0 | 4.4.1 |
| docker/login-action | 4.5.1 | 4.8.0 |
| docker/build-push-action | 7.2.0 | 7.4.0 |
| Docker Scout release CLI | 1.20.4 | 1.29.0 |
| TruffleHog | 3.96.0 | 3.99.9 |
| Syft | 1.42.4 | 1.57.1 |
| Grype | 0.110.0 | 0.121.3 |
| trivy-action | 0.36.0 | 0.36.0 |
| Trivy engine | 0.69.3 | 0.76.2 |
| softprops/action-gh-release | 3.0.2 | 3.0.4 |

Also reconcile README/SECURITY claims of a checked-in CodeQL workflow with the
three current workflow files; externally configured/default scanning was not
verified. Root MAKEFILE `test`/`build` invoke Go outside the nested module and
`docker` uses a context without a root Dockerfile; correct these maintenance
commands when implementing the update slice.

## Validation and limits

- Declared Go 1.26.8: tests, vet, build, and tidy-diff pass using public CI-only
  test keys supplied in process environment. Initial tests without DATA_KEY
  failed at startup; the configured rerun passed.
- Candidate Go 1.26.11: tests, vet, module verification, tidy-diff, and source
  vulnerability scan pass, with the module-only exception described above.
- Admin JavaScript smoke tests pass. No real provider/browser/MFA/database
  integration acceptance was performed.
- Docker Desktop was started for read-only registry scans. No Compose services
  or database volumes were changed.
- Inspecting `dhi.io/golang:1.26.11-alpine3.23-dev` failed with HTTP 401 obtaining
  a registry token. Candidate tag existence, builder/runtime digests, package
  contents, and a rebuilt production image remain unverified. Use an authorized
  DHI login before choosing pins; do not silently change image families.
- PostgreSQL arm64 and database upgrade/restore behavior remain untested.

## Primary references

- [Go release history](https://go.dev/doc/devel/release)
- [LDAP 3.4.15 release notes](https://github.com/go-ldap/ldap/releases/tag/v3.4.15)
- [Go vulnerability database](https://vuln.go.dev/)
- Individual Go advisories: `https://pkg.go.dev/vuln/GO-2026-NNNN` using the IDs above.
- [Docker Scout CLI releases](https://github.com/docker/scout-cli/releases)

## Implementation checkpoint

After Docker login was restored, the maintenance branch was updated:

- Go toolchain/CI/docs: 1.26.11; LDAP: 3.4.15; x/crypto: 0.59.0.
- Hardened builder index:
  `sha256:b67835d53e07cda04291aba44d65d3eace427d9eb61693b7e2819ccafa48c8fe`.
- Hardened runtime index:
  `sha256:8a14cb527704fd6325fae6e92e0bc73a3c64b44a83c36a3abb53730c5757cc72`.
- Applied the action/scanner releases listed above, with action commit pins,
  Scout image digest, and upstream Syft/Grype SHA256 checksums. Attest was already
  at the current commit; its version comment was clarified.
- Added pinned govulncheck 1.9.0 to CI; corrected Dependabot's Go directory and
  added Dockerfile coverage; repaired Makefile module/build paths.
- Replaced unverified CodeQL scheduling claims with the checked-in govulncheck
  behavior and corrected Docker Scout's documented release scope.
- Retained PostgreSQL 15.19's digest. The assessed 15.20-trixie image does not
  resolve its critical package findings; choosing a different image family and
  validating an existing database remain separate work.

Validation after implementation:

- Go tests, vet, module verification, tidy-diff, and admin JS smoke pass.
- Source govulncheck reports **no vulnerabilities**, including module level.
- Actionlint 1.7.12 passes (external shellcheck/pyflakes disabled).
- Both amd64 and arm64 production images build; extracted binaries identify
  Go 1.26.11, the expected GOARCH, and CGO_ENABLED=0. Both retain UID/GID 65532.
- Local Scout 1.27.0 reports **zero findings of every severity** for both images.
  Local image IDs: amd64
  `sha256:72d3e3df0bf12a8a3109e6861efcb942d729bbb633c3dd19c597801d0f0cf318`,
  arm64 `sha256:c7a13d7e794a70c2ba7b4181e2d90723d176803cdecc57f4efb945b7967b43be`.
- Updated Syft 1.57.1 generates a CycloneDX SBOM; updated Grype 0.121.3 reports
  no vulnerabilities from that SBOM. Stripped binaries do not carry function
  symbols, so this scan uses module-level matching.
- Updated Trivy 0.76.2 passes the release-equivalent fixed HIGH/CRITICAL gate
  on the amd64 image with zero matching findings.
- The amd64 image initializes against an isolated PostgreSQL 15.19 database
  using disposable tmpfs storage. `/healthz`, `/readyz`, `/startupz`, and `/`
  return HTTP 200. Test containers and their network were removed; no existing
  services or database volumes were changed.

The initial DHI authentication and source/image findings above are baseline
evidence, not current blockers or findings for the rebuilt application images.
Remote publication/attestation and real database upgrade acceptance remain
outside local validation.

Delivery checkpoint: the operator accepted UAT of the temporary multi-platform
`modomofn/auth-portal:uat-f2b63d0` image. PR #180 targets `main`; its initial head
`f2b63d0` passed all nine GitHub checks, including CI, SonarCloud, and CodeQL.
This confirms repository-configured CodeQL scanning despite the absence of a
checked-in CodeQL workflow. UAT acceptance does not enumerate individual
provider/MFA scenarios, so it is not a claim that every integration was tested.
The latest published release remains v2.0.6; maintenance changes await a new
version/tag. The proposed next patch release is v2.0.7.
