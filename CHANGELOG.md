# Changelog

All notable changes to this project will be documented in this file.

This changelog covers both the DevGuard API (`devguard`) and the web frontend (`devguard-web`).
## [v1.10.2] - 2026-07-20

- Just linter fixes

## [v1.10.1] - 2026-07-20

### Changed

- **Compliance posture permissions** — changing an organization's compliance posture is now restricted to org admins, instead of any org member

### Fixed

- **`devguard-maint release helm-chart`** — no longer fails when `docker-compose-try-it.yaml` is already up to date (previously tried to commit an empty diff and aborted); the command now regenerates the Helm chart's `values.yaml`/`Chart.yaml`/`questions.yaml` via `devguard-helm-chart/schema`'s `bun run generate` instead of hand-rolled regex edits, and also verifies a matching `devguard-ci-components` release exists before proceeding

## [v1.10.0] - 2026-07-20

Thanks to @nicksan222 for their first contribution to DevGuard! 🎉

### Added

- **Compliance posture** — a new compliance module tracking framework controls and posture per project/org, seeded from the Grundschutz++ and Secure Controls Framework (SCF) catalogs, with a new API (`compliance_posture_controller`) and OSCAL/CSAF-based control mappings
- **OSCAL component support** — compliance components can now be ingested from an OSCAL component definition (with a Grundschutz control mapping), stored, and queried per project, including filtering for vulnerabilities that are solvable via a given component
- **Evidence links in OSCAL export** — the OSCAL/compliance posture export now includes evidence links back to the originating findings
- **Advisory tab (first approach)** — a new advisory feature backed by its own model, repository, state machine, and CSAF-driven service, exposed through a dedicated advisory API and router
- **Faster SCA scanning** — `devguard-scanner sca` can now use an embedded Trivy source DB for faster scans
- **Component reparenting in SBOMs** — root components' direct children are now reparented under the detected artifact name during SBOM normalization, improving dependency tree accuracy for SARIF/SCA scans

### Changed

- **Database health check** — the health check endpoint now fails when the PostgreSQL pub/sub listener disconnects, instead of reporting healthy while broker notifications are silently lost ([#2589](https://github.com/l3montree-dev/devguard/issues/2589))
- Compliance migrations renamed/reordered for consistent ordering after the compliance posture and OSCAL components features landed side by side

### Fixed

- **Vulnerability report PDF generation (opencode template)** — added the missing highlighting-macros include to the opencode LaTeX template, fixing PDF generation for that report style

## [v1.9.3] - 2026-07-15

### Added

- **GitHub issue reconciliation** — DevGuard now closes stray GitHub issues that carry the `devguard` label but no longer correspond to a tracked vulnerability for the asset, mirroring the reconciliation already available for other providers

### Changed

- **Unified "not connected" handling** — GitHub, GitLab, and Jira integrations now share a single `commonint.ErrNotConnected` error instead of each defining their own, so the asset pipeline can swallow the error consistently across providers; Jira sync errors are now also swallowed when the integration is not connected
- `licenses` command moved from `devguard-cli` to `devguard-maint`
- Added highlighting-macros include to the vulnerability report LaTeX template, fixing PDF generation (https://github.com/l3montree-dev/devguard/issues/2120)

### Fixed

- **GitHub issue comparison** — corrected the logic used to compare tracked vulnerabilities against existing GitHub issues

## [v1.9.2] - 2026-07-14

### Fixed

- **Ory Kratos connectivity** — the Ory API client now uses its own dedicated HTTP client instead of the shared egress client, working around the new egress SSRF protections blocking the configured Ory domain in some deployments

### Changed

- Removed now-redundant per-integration rate limiters in the GitLab client factory and the open-source-insights service, since outgoing requests are already rate-limited per host by the shared egress client
- Refreshed the dependency license manifest (`licenses.json`)

## [v1.9.1] - 2026-07-14

(Multiple security fixes. Information on the vulnerabilities will be added later.)

## [v1.9.0] - 2026-07-14

Thanks to @domzoric for their first contribution to DevGuard! 🎉

### Added

- **SBOM enrichment & Nix build SBOMs** — major overhaul of SBOM generation: implements a `sboms` directory standard, extracts SBOMs from OCI image tar files, and enriches generated SBOMs with external references; Nix-built images now produce a corrected, self-describing SBOM during OCI image builds
- **CSAF VEX ingestion** — a new CSAF VEX report endpoint per artifact is used to ingest VEX statements during SBOM generation, and dependency vulnerability scans now ingest VEXes automatically
- **Invitation revocation & expiry** — organisation invitations can now be revoked and carry an expiry date/time, surfaced through new DTOs and returned to the frontend
- **Bulk selection for code risk (web)** — added multi-select support for bulk-updating code risk findings
- **Artifact-scoped badge route** — the authenticated badge endpoint is now also exposed per artifact (`.../refs/:assetVersionSlug/artifacts/:artifactName/badges/:badge/`), matching the scoping already available on the public share router, so the badge preview reflects the selected branch/tag/artifact ([#2198](https://github.com/l3montree-dev/devguard/issues/2198))
- **`--print-token` flag** — `devguard-scanner auth` can now print the resolved token for debugging
- **Flag passthrough for `devguard-scanner`** — arbitrary flags can now be forwarded to the underlying scanner using a double dash (`--`)
- **`--path` argument for SCA** — the SCA scan command now accepts a path argument to scan a specific directory

### Changed

- **SBOM artifact strategy** — when multiple SBOMs are supplied for the same artifact, the last one now wins instead of merging, simplifying re-scan semantics
- **Asset name normalization** — asset names are now normalized consistently, fixing links that previously pointed to the wrong URL
- **Unresolved component warnings** — components are now checked transitively for versioned children before being reported as unresolved
- **GitHub label handling** — labels are deduplicated (can occur after truncation) and truncated to GitHub's 50-character limit
- **Risk threshold calculation** — fixed an inverted open/closed condition when evaluating risk thresholds
- **Dependency updates** — Go, Python (including a `soupsieve` patch to 2.8.4, and `pyjwt` to 2.13.0), and `oras-go` (to v2.6.1) dependencies updated; Ory Kratos updated to v26.2.0; Trivy updated

### Fixed

- **VEX rule SQL error** — fixed a broken SQL query in VEX rule handling
- **Exploits table truncation** — the exploits table is now truncated correctly on reset, and an obsolete foreign key drop was removed
- **Attestation map** — fixed an issue in the attestation output map, with added unit test coverage
- **Result printing link** — fixed a broken link shown when printing scan results
- **Quick fixes** — corrected an issue in the quick-fix flow
- **CI hardening** — removed a code-scanning pin, pinned the release action and `cache-nix` action, and fixed a hardcoded API URL used in CI

## [v1.8.0] - 2026-07-01

### Added

- **Automatic ownership scoping** — GORM repositories now enforce ownership/tenant scoping automatically at the query layer, closing off a class of cross-tenant data leakage (BOLA) that previously relied on each repository remembering to filter manually; covered by a new `semgrep` rule set and repository-level tests
- **Dynamic external project handling** — new endpoints and routing to create, list, and delete projects/assets backed by external providers, including a project tree transformer, release population on project creation, and e2e coverage
- **`devguard-maint release k8s-integration`** — new subcommand to tag and push the `devguard-k8s-image-inventory` repo, following the same changelog-verification and signed-tag flow as the other release commands

### Changed

- **Instance settings cache** — settings updates now synchronize the in-memory cache immediately (with proper mutex protection), avoiding a window where stale settings could be served after an update

### Fixed

- **In-toto path traversal / zip-slip** — the in-toto controller and service now validate link file paths, preventing path traversal and zip-slip when processing in-toto attestations
- **CI/IaC hardening** — CI pipeline no longer swallows code-scanning failures, Checkov IaC findings addressed, and a previously dropped Semgrep severity rule was restored

## [v1.7.3] - 2026-06-23

### Added

- **Telemetry on startup** — DevGuard now sends anonymous telemetry to the instance's configured Umami endpoint when starting up; runs in a background goroutine so it does not block the HTTP server; respects an opt-out env var and logs a info message when disabled

### Changed

- **Semgrep output** — Semgrep scanner output is now logged at `WARN` level instead of `DEBUG`, making SAST scan issues easier to spot in production logs

### Fixed

- **GitLab issue creation** — the GitLab integration now returns the created issue even when the follow-up comment creation fails, preventing a silent no-op when the comment endpoint errors

## [v1.7.2] - 2026-06-23

### Added

- **`devguard-maint` CLI** — new Go-based maintenance tool under `cmd/devguard-maint` replacing the old shell release scripts; provides `release devguard`, `release web`, `release helm-chart`, `release ci-components`, and `docs` subcommands with changelog-entry verification, automatic version detection, and signed tag support
- **Versioning documentation** — `VERSIONING.md` added to the repo root explaining the shared-minor-version strategy across all DevGuard components; compatibility guarantees and a component table are also surfaced in the installation docs and release bodies

### Fixed

- **CI release pipeline** — `devguard-scanner.yaml` now correctly extracts the minor version for release notes and marks `-rc`/`-alpha`/`-beta` tags as GitHub prereleases; `devguard-cli` binary is included in the release artifacts

## [v1.7.1] - 2026-06-22

### Changed

- **Go modernization** — codebase updated with `gopls/modernize` to use current Go idioms (e.g. `min`/`max` builtins, loop variable capture, slice/map literals); no behaviour changes
- **Ticket creation logging** — GitHub, GitLab, and Jira integrations now log when ticket creation is skipped or triggered, making dry-run and live pipeline debugging easier
- **CSAF controller cleanup** — removed unnecessary pointer indirection (`Ptr` calls) in `csaf_controller.go` and `csaf_service.go`; safe nil-dereference via `utils.SafeDereference` in the dry-run integration

## [v1.7.0] - 2026-06-19

### Added

- **Instance admin dashboard** — the instance-wide admin area introduced in v1.6.1 is now functional: the actions are wired to their backend endpoints, an "Organisation Creation" toggle gates whether users may create organisations, and the dashboard surfaces instance settings, technical info, and daemon triggers. Admin requests are signed in the browser using an in-memory signing key, and the admin session now expires after a configurable timeout
- **`decrypt` CLI command** — counterpart to the existing `encrypt` commands, decrypts secrets for inspection/debugging
- **Daemon asset-pipeline dry-run** — a `--dry-run` flag on the daemon asset pipeline runs the full pipeline without persisting results or firing integrations (new in-memory dry-run integration), simplifying debugging of GitHub/GitLab/Jira ticket flows

### Changed

- **RBAC rule cleanup on deletion** — deleting an organisation, project, or asset now cascades to remove its Casbin RBAC rules instead of leaving them orphaned; a migration cleans up rules orphaned by previous deletions. Org creation also returns a more expressive error on failure
- **SAST scanning** — SAST suppressions are stripped before upload, scanner config discovery was improved, and Semgrep debug output was added; the project Semgrep config moved to `.semgrep.yml`
- **SSE streaming (web)** — the admin daemon-trigger streaming was refactored into a reusable `src/lib/sse.ts` helper; signed request bodies are now enforced as strings and SSE CRLF line endings are handled correctly
- **CI / e2e tooling** — pipelines migrated from `devguard-action` to the reusable `devguard-ci-component`; Playwright e2e suite reworked with a dedicated auth setup and updated Playwright/Ory versions

### Fixed

- **Scan v2 authorization** ([#2163](https://github.com/l3montree-dev/devguard/issues/2163)) — authenticated `/api/v2/scan` and `/api/v2/sarif-scan` endpoints now require only `read` on the asset (down from `update`) and reject public requests; fixes a 500/authorization regression for CI scans
- **Panic in `getBestDescription`** — guards against a nil-pointer panic when a SARIF reporting descriptor lacks description fields
- **Missing SARIF URI** — the unauthenticated SARIF scan path no longer drops the result URI in the generated SARIF
- **Config file editor (web)** — config-file editor filenames now match what the scanner expects
- **Dashboard stats (web)** — instance dashboard statistics are rounded to two decimals; dashboard loading/error states and a login-domain warning were corrected

## [v1.6.1] - 2026-06-17

### Added

- **pprof basic auth** — profiling endpoints (`/debug/pprof`) are now protected by HTTP Basic Auth when the `PPROF_PASSWORD` environment variable is set; the Helm chart auto-generates and persists the password as a Kubernetes secret; the password is logged on startup
- **Instance admin dashboard** (unfinished) — new `/admin` routes exposing instance-wide statistics (top CVEs, top components, malicious packages, average open risks, most vulnerable projects); asymmetric-key-based admin authentication via `devguard-cli gen-admin-key`; admin-scoped RBAC; daemon trigger endpoints with a 5-minute rate limit; separate admin router and controller

### Fixed

- **Goroutine leak in `errGroup`** — a `defer eg.startCollecting()` in `WaitAndCollect` pre-armed a new collector goroutine that was never drained when the `errGroup` was not reused, causing goroutines to accumulate unboundedly; fixed with a lazy re-arm via a `needsReset` flag checked in `Go`

### Changed

- **HTTP client hygiene** — all outgoing HTTP clients now use `utils.EgressTransport` (adds `User-Agent` and OpenTelemetry trace propagation) and carry explicit timeouts; `http.NewRequestWithContext` is used throughout; enforced via three new semgrep rules (`http-new-request-without-context`, `http-client-missing-egress-transport`, `http-client-egress-transport-missing-timeout`)
- **Context threading** — `ctx context.Context` propagated through repository and service method signatures that were missing it; repository methods consistently carry `tx *gorm.DB` as a second parameter

## [v1.6.0] - 2026-06-16

### Added

- **App-side encryption** — integration secrets (GitLab, Jira, webhook tokens) are now encrypted at rest using AES-GCM with an operator-provided key; a `devguard encrypt migrate` CLI command re-encrypts existing plaintext secrets (offline only), and a `devguard encrypt rotate` command swaps to a new key without service downtime; the `--key` flag on the migrate command allows seeding the key file on first-time setup
- **PAT expiry dates** — Personal Access Tokens now carry a mandatory expiry date (default 365 days); expiry is enforced at authentication time
- **Bearer token auth for scanner** — the scanner now accepts symmetric bearer tokens (PATs) in addition to session cookies; a new `devguard-scanner auth` command stores the token in the system keyring with a local-file fallback
- **Scan v2 endpoints** — new `/scan/v2` API routes return VEX and SARIF directly in a single response; v1 scan endpoints are marked deprecated in Swagger docs; scanner CLI updated to invoke v2 by default
- **Unauthenticated SARIF upload endpoint** — CI pipelines can push SARIF results without a session token; directory scan mode added for secret scanning
- **Scanner `--noWrite` flag** — scanner runs without persisting results (dry-run mode)
- **VulnDB relationship data** — `/vulndb` endpoints now include related CVE/GHSA relationships in responses
- **Golang license case-insensitive fallback** — Go module license resolution retries with a `v`-prefixed version when the bare version returns no result

### Changed

- **Dependency path in integration tickets** — GitHub, GitLab, and Jira tickets now render the component dependency tree directly from the stored `vulnerability_path` field ([#2144](https://github.com/l3montree-dev/devguard/issues/2144)) instead of re-querying the component graph on every ticket update, removing a database round-trip per ticket operation
- **RBAC mutex** — Casbin enforcer uses `RLock` for read operations instead of a full write-lock, reducing contention under concurrent requests
- **SCA scanner output** — terminal print output improved; VEX documents now include CVE description, corrected source link, vulnerability path, and `directDependencyFixedVersion`
- All Go dependencies updated; Go toolchain bumped to v1.26.3

### Fixed

- Reauthorization errors now return HTTP 403 with a specific `reauthorize` error code so clients can distinguish token expiry from other auth failures
- Missing avatar URLs in sub-project and asset list queries
- Pull request finding edge case that could miss findings in certain repository states

## [v1.5.1] - 2026-05-28

### Fixed

- Hash migration v4 no longer re-runs on every startup — the config version was not persisted after the full vulndb re-import, causing it to trigger again on each restart

## [v1.5.0] - 2026-05-28

### Added

- Packagist integration — DevGuard now queries Packagist to enrich PHP package metadata and licensing information
- Single artifact sync endpoint re-added — the per-artifact sync endpoint was restored along with a missing trailing slash in the Swagger docs
- QuickFix direct dependency support — an `if` statement guard ensures the quickfix path applies correctly to direct dependencies
- Programmatic CI support — DevGuard CI workflows now use reusable `devguard-ci-components` / `github-v1` workflow references

### Changed

- Component dependencies table overhauled — composite primary key replaces the surrogate `id` column; obsolete indexes and columns removed; SBOM graph normalisation updated accordingly
- All dependencies updated; reusable GitHub Actions workflow references updated to `github-v1`
- Content-Length header is now forwarded through the OCI proxy

### Fixed

- License risks not being closed correctly; Packagist DTO parsing fixed
- Open source insight service: incorrect variable declaration in `getVersion` default case
- Go license version prefix — versions without the `v` prefix are now retried with it
- VulnDB: `lastAffected` ranges in OSV transformation were not respected
- Migration retry — opens a new connection pool after closing the migrator to avoid `sql: database is closed` errors
- Maven vulnerability fixed-version resolution
- Sitemap `listIDsByCreationDate` endpoint column mismatch

### Web

#### Added

- Theme toggler — light/dark mode toggle on sign-in and sign-up pages
- Star/GitHub banner
- CVSS badge shown in risk handling view (users were confused by the absence of CVSS highlighting)
- Guided tour hints — contextual hints added to existing first-access tours

#### Changed

- QuickFix: fallback to direct dependency removed (handled in backend); hidden when there are too many paths
- Risk badge reworked
- `RiskGroup`: "across other branches" suffix removed
- Link colours made consistent across components; drawer button link uses `--link` CSS variable
- Code colour fixed to black in light mode

#### Fixed

- Filter button styling
- Link colour inconsistency across the application
- Description/code colour in Markdown component
- Gitleaks config editor now uses TOML format
- Member invitation dialog: improved contextual descriptions and sub-project support
- Package URL qualifiers truncated to prevent display overflow
- Invalid package URLs now return `null` instead of throwing

### Contributors

[@iccccccccccccc](https://github.com/iccccccccccccc) — Go license v-prefix fix, Gitleaks TOML fix; [@resolvicomai](https://github.com/resolvicomai) — truncate PURL qualifiers

## [v1.4.2] - 2026-05-20

### Fixed

- SBOM graph normalization panicked when a component had multiple info-source parents — multi-parent cases are now handled
- Cascade delete for `github_app_installations` and `artifact_license_risks` — installations and license risks are removed when their parent records are deleted (migration uses the correct `license_risk_id` column name)
- **Web:** PDF download path; autosetup loading state on failure

### Added

- `DisablePublicRequest` middleware to enforce the public-request toggle at the route level, with router tests verifying it is applied to the intended endpoints

### Contributors (Web)

[@seb-kw](https://github.com/seb-kw); external: [@resolvicomai](https://github.com/resolvicomai) (Mauro Marques Filho) — autosetup fix

## [v1.4.1] - 2026-05-19

### Fixed

- Nil pointer dereference in `asset_version_service`
#### API
- Nil pointer dereference in `asset_version_service`

#### Web
- last-active-org redirect: SSR hydration mismatch
- localStorage placeholder-org guards, session update on org registration
- streaming-chunk buffering for newline-delimited JSON parsing
- SBOM/SARIF order in the own-scanner upload flow


### Changed

- **Web:** CVE marked optional on vulnerability views (matches backend foreign-key removal); lightmode severity colors adjusted for contrast

### Contributors (Web)

[@timbastin](https://github.com/timbastin), [@refoo0](https://github.com/refoo0), [@juliankepka](https://github.com/juliankepka)

## [v1.4.0] - 2026-05-19

### Added

- VulnDB v2 — Complete rewrite of the vulnerability database pipeline. The published VulnDB image is now distributed as a single streaming bundle of gob-encoded, Zstandard-compressed datasets (CVEs, affected components, CVE relationships, EPSS, CISA KEV, exploits, and malicious packages), replacing the previous model of fetching multiple data sources at runtime. In addition, every table is checksummed during the GitHub Actions build process, and the resulting artifact embeds metadata containing these checksums. After both quick-diff and full streaming imports, integrity is verified by ensuring the imported state matches the original build output using Merkle-tree-based validation.
- Quick-diff incremental updates — VulnDB clients apply only the rows that changed since the last sync via a stage-table EXCEPT-based diff, with a streaming fallback if quick-diff fails and a monitoring alert when it does
- Streaming imports — Streaming transformers pipe gob files into PostgreSQL using buffered channels and bulk inserts; staging tables are flushed once per stream; index rebuild is triggered if the local vulndb is older than 7 days
- Embedded vulndb cosign public key — The cosign pubkey used to verify the vulndb image is embedded in the DevGuard binary; content-hash columns added to malicious packages and exploits for integrity verification
- Crowdsourced VEX — Recommendation algorithm with project-based recommendations, vote keying, VEX rules included in recommendation output, and matching DTOs
- Deep search — Search endpoint that returns projects together with their subprojects and assets in a single query
- Admin instance settings — Endpoint and middleware to read and update instance-level settings; `DISABLE_ORG_CREATION` config option for single-organization deployments
- OCI proxy hardening — SSRF protection for the public OCI dependency proxy; path-parameter validation; GitLab registry support;
- User-agent propagation — User agent threaded through controllers, services, and integrations (events, license decisions, Jira); `user_agent` column on the events table; MCP-server `CreateEvent` calls are tagged accordingly
- Fixable CVSS counts in risk statistics; risk calculation uses the highest risk per CVE/PURL pair. This builds upon the QuickFix Algoritm (https://docs.devguard.org/explanations/supply-chain-security/transitive-vulnerability-path-analysis/)
- Daemon pipeline timeout raised to 2 hours to surface stuck imports instead of blocking the queue
- Integration tests for scoped SBOM scans with artifact-specific vulnerabilities
- OpenTelemetry spans on vulndb `ImportRC` and `checkIfTokenIsValid`, including retry attributes
- Dedicated health-check database connection; db-stats logging on failing health checks

### Changed

- VulnDB export now writes a single zip of gob files with deterministic ordering and timestamp consistency between OSV CSV and stored records; checksum is computed after import and the `modified_id.csv` file is mirrored on fetch
- VulnDB import: parallel work and on-the-fly table truncation; only reachable CVEs are stored; CISA KEV and EPSS enrichment is deterministic and applied directly (no relationship expansion); tie-breaker added for CISA KEV import
- `cves` table — surrogate ID column added; primary key on the old text column dropped; CISA and EPSS values are part of the table checksum
- CVE references on `dependency_vulns` and `vex_rules` are now nullable, allowing rows to survive a CVE wipe
- `ProjectAssetDTO` field renamed from `type` to `resourceType` (queries updated accordingly)
- Vulnerability state update no longer filters by `deleted_at` when selecting the last event; legacy `fixed`/`reopened` system events from the `system` user are deleted and state is rebuilt
- Down migrations removed — migrations are forward-only
- Dependencies updated; `go-git` bumped to a non-vulnerable version; Python `urllib3` patched to 2.7.0
- Docker Compose `try-it`: corrected image versions, added `tmpfs` mounts for `/run/postgresql`, `uid`/`gid` flags added

### Fixed

- SBOM graph path finding — extends through component parents and respects scope during path resolution; nil check added after the termination-condition change
- Incremental import silently skipping new CVEs with stale modified timestamps
- Partial imports not applying EPSS and CISA KEV data
- Exploits table being wiped via cascade delete — exploits are retained and CVE-affected-components are deleted dynamically with a scoped cleanup job
- Migration hanging; migration connection leakage
- Integrity verification failing because of missing EPSS values
- Quick-diff fallback running on the original (poisoned) transaction; now uses a new transaction
- "Cannot scan NULL to string" error during vulndb import
- Duplicate entries in `failingTables` during integrity validation
- VulnDB queries are case-insensitive
- Wrong HTTP status code on a public endpoint
- Preallocated-slice bug in vulndb export
- Defer rollback bug; orphan CVE entries left in the database after import

### Web

- **Added:** Reactour-based guided tours and help center (org settings + three more flows); DocDrawer component for inline docs; tools dropdown (package inspector, vulnerability database); subgroups + assets shown in one list with active-state search (min. 3 chars); collapsible group headers in the risk assessment feed; AI-applied actions indicated on event messages (uses `userAgent` from backend); crowdsourced VEX display; share VEX/SBOM option in the "Share your…" modal; last active org remembered across sessions; quickfix badges and CVSS quickfix variants; tooltip on recommendations; robots.txt; mobile support page; Umami tracking on help center, tours, and docu
- **Changed:** Glacier theme refined and set as default; CSS consolidated into semantic tokens with new `--grid-line-color`; client-side fetching used for the landing-page tunnel; `devguard-landing-page-tunnel` added; member-invite form cleared after success; copyright year bump; Next.js → 15.5.18, lodash refreshed
- **Fixed:** Welcome modal logo and white-on-white image bug; inner-scrollbar issue replaced by a fully scrollable modal; skeleton loader consistency on org/project lists; VEX modal manual button and column alignment; misc border, spacing, and icon cleanup; help dropdown Umami location

### Contributors

Thanks to everyone who contributed to this release:
[@timbastin](https://github.com/timbastin), [@Hubtrick-Git](https://github.com/Hubtrick-Git), [@Dboy0ZDev](https://github.com/Dboy0ZDev), [@refoo0](https://github.com/refoo0), [@seb-kw](https://github.com/seb-kw), [@juliankepka](https://github.com/juliankepka), [@5byuri](https://github.com/5byuri)

Special thanks to external contributors [@gauravshinde1729](https://github.com/gauravshinde1729) for the OCI proxy SSRF hardening and kill switch, and [@mine-13-zoom](https://github.com/mine-13-zoom) for the admin org-settings endpoint.

## [v1.3.1] - 2026-04-28

### Fixed

- Wrong digest verification — Added trim suffix to correctly parse and compare image digests (oci dependency proxy)
- PostgreSQL exporter tag being updated unintentionally during release
- Go scanner helper binaries — Added `CGO_ENABLED` flag to ensure static binaries

### Changed

- Release scripts — Added confirmation message before applying changes; files are now auto-staged after confirmation
- Helm chart — `values.yaml` is now included in release script updates

## [v1.3.0] - 2026-04-27

### Added

- **OCI Dependency Proxy** — New proxy for OCI registries with content digest verification, protecting against supply chain attacks
- **Package Rules** — Configurable allow/block patterns for NPM, PyPI, and Go packages; path traversal protection built in
- **Dependency Proxy Secrets** — Per-organization/project secret management for authenticated upstream registries; dedicated ecosystem controllers with independent routing per package manager
- **Renovate Integration** — New recommendation endpoint returning update suggestions scoped to `packageName` and `currentValue`
- Daily fixable vulnerability history now tracked per artifact and exposed via API
- Vulnerabilities are automatically reopened with an event when re-detected in subsequent scans
- Quickfix dashboard statistics: vulnerability distribution added to artifact risk history
- All DevGuard images now built with Nix for fully reproducible, hermetic builds with multi-architecture support (AMD64 + ARM64); Python dependencies (Semgrep, Checkov) built via `uv2nix`
- `DISABLE_TICKET_SYNC` environment variable added

### Fixed

- Webhook retry logic now only retries on 5xx, 408, and 429 responses
- Remote descriptor retrieval in attestation fetching now authenticates correctly
- VEX rules not applying for direct dependencies; `ROOT` wildcard removed
- SARIF upload size limit enforced with nil-pointer guards
- CVSS conversion panics from OSV data removed
- Search query trimming fixed to use whitespace-specific function

### Changed

- Internal vulnerability IDs migrated to 128-bit UUIDs (fully transparent — no API changes)
- Mutex guards added around Casbin enforcer calls to prevent race conditions

### Contributors

Thanks to everyone who contributed to this release:
[@timbastin](https://github.com/timbastin), [@Hubtrick-Git](https://github.com/Hubtrick-Git), [@refoo0](https://github.com/refoo0), [@Dboy0ZDev](https://github.com/Dboy0ZDev), [@seb-kw](https://github.com/seb-kw), [@5byuri](https://github.com/5byuri), [@juliankepka](https://github.com/juliankepka)

Special thanks to the external contributor [@gauravshinde1729](https://github.com/gauravshinde1729) for fixing VEX rules for direct dependencies!

## [v1.2.3] - 2026-04-23

### Fixed

- Remote authentication flow for attestations now works correctly when fetching attestations

## [v1.2.2] - 2026-04-22

### Fixed

- Security vulnerability in middleware implementation (more details will be added later)

## [v1.2.1] - 2026-04-08

### Fixed

- Renaming an asset, project, or organization no longer overwrites its slug — slugs are now immutable after creation, preventing broken URLs and references when a resource is renamed

## [v1.2.0] - 2026-03-30

### Added

- New VEX and SBOM endpoints on asset versions — clients can now retrieve VEX documents and SBOM data directly from asset version routes; the artifact service was updated to collect and surface VEX information alongside SBOM graphs
- `MergeGraph` now tracks removed nodes and edges so callers can detect deletions when merging two SBOM graphs
- Config-file management endpoints for asset, organization, and project controllers — authenticated clients can read and update their DevGuard config files via the API; the scanner gained matching support for writing config files to disk
- RBAC authorization added to the organization overview dashboard endpoint
- Crowdsourced VEX algorithm: calculates a confidence/trust score for VEX justifications based on community signals, using an exponential-decay diminishing function and tie-breaking logic; includes a new CLI command to generate trust scores for organizations and projects
- Quick Fix feature: given a vulnerable PURL, the API resolves recommended fixed versions by querying upstream package registries (NPM, Debian) and walking the dependency tree to find the closest safe version; supports semver constraints and optional dependencies

### Changed

- CSAF HTML index: unified title generation and vulnerability fetching across yearly index pages; events are now chunked together for more coherent report sections; index entries are cached for 12 hours to reduce redundant database queries
- CSAF report title logic and tracking ID generation revised; revision entry ordering corrected; textual summary of revision history entries updated
- NPM fixed-version resolver migrated to full semver parsing and constraint evaluation; no longer writes a `package.json` to disk as a side effect
- Debian package mapping: `packages.xz` parsing memory footprint reduced from ~70 MB to ~9 MB by using a single arena allocation and token-based lookup instead of building a full map
- Vulnerability code snippets exceeding 10 KB are now dropped before storage to prevent excessive database bloat
- Jsonnet user mapper updated to fall back to GitHub login when no explicit name is available
- `isCVE` helper function rewritten to use a regex for stricter CVE-ID validation
- Orphaned record cleanup (`CleanupOrphanedRecordsSQL`) is now managed by a dedicated background daemon, replacing the previous fire-and-forget goroutine

### Fixed

- Nil pointer panic in the Debian package resolver when processing packages without version information; Debian package mapping files removed as they are no longer used
- Double asset-version entries created when processing PURLs with identical coordinates
- Inconsistent product-ID construction in CSAF reports leading to mismatched references
- Incorrect SQL `COALESCE` syntax in statistics queries
- Null values appearing in average-score aggregations
- Total-count query returning incorrect results for vulnerability statistics
- Org risk history endpoint returning stale or incorrect data

## [v1.1.1] - 2026-03-23

### Fixed

- Vulnerability state incorrectly inherited `fixed` status from other branches — `fixed` events from other asset version branches are no longer applied to a vulnerability that is still actively detected on the current branch
- `SaveBatchBestEffort` failed repeatedly after the first PostgreSQL "extended protocol limited to 65535 parameters" error because the transaction was left in an aborted state — savepoints are now used so the transaction remains usable for split-and-retry attempts

## General notes

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release notes MUST identify every publicly known run-time vulnerability fixed in this release that already had a CVE assignment or similar when the release was created.

You can find the public key for verifying the image and SBOM signatures here: [cosign.pub](https://github.com/l3montree-dev/devguard/blob/main/cosign.pub)

## [v1.1.0] - 2026-03-17

### Security

- No publicly assigned run-time CVE fixes were identified in this release window.

### Added

- Consolidated organization statistics in DevGuard API server, including additional metrics for CVEs, open vulnerabilities, first-party vulnerabilities, component age, ecosystems, and risk history endpoints.
- New tracing and observability capabilities in DevGuard API server and deployment manifests, including OpenTelemetry instrumentation, trace context propagation, Jaeger integration, span metrics, and Helm support for tracing options.
- Scanner and policy capabilities in DevGuard API server and supporting components, including policy loading from URL and additional scanner output metadata.
- DevGuard Helm chart updates for tracing, ServiceMonitor connector endpoint support, and Kyverno policy support for build provenance verification.
- DevGuard CI component enhancements for attestation pipeline orchestration, including improved source attestation flow, job dependency handling, and scanner update to v1.1.0.
- DevGuard Web improvements, including a structured cross-page filter system for risk views, billing URL handling for payment-required flows, dynamic issue tracker URLs, and onboarding/project configuration refinements.

### Changed

- DevGuard API server SQL queries and statistics implementation were refactored for better performance and consistency, including query parallelization, endpoint consolidation, and interface cleanup.
- DevGuard API server security data ingestion changed by removing Debian Security Tracker synchronization and related workflow/import logic.
- DevGuard API server build and runtime stack changed with dependency refreshes, Go upgrade to 1.25.7, and migration from standalone cosign binary usage to library-based signing.
- DevGuard Web remediation-time and dependency/risk UI logic were refactored to align with unified backend endpoints and updated filtering semantics.

### Fixed

- DevGuard API server fixed stack overflow conditions in SBOM processing via node elision and test coverage.
- DevGuard API server fixed transaction commit behavior, tracing context issues across external providers, dependency proxy tracing bugs, and edge cases in remediation-time queries.
- DevGuard API server fixed image tag generation to sanitize slash characters in generated tags.
- DevGuard Helm chart fixed Kyverno policy issues and namespace handling in chart resources.
- DevGuard CI component fixed YAML formatting/syntax issues and corrected attestation job configuration regressions.
- DevGuard Web fixed compliance visibility toggling, CVSS badge image source handling, asset-version deletion flow behavior, and several UI consistency regressions.

## [v1.0.1] - 2025-03-03

### Added

- Unauthenticated scanning: assets can now be scanned without requiring authentication, enabling easier integration into public CI/CD pipelines
- `sbom validate` CLI command to validate CycloneDX SBOMs before uploading
- SBOM reading from stdin in the CLI (`devguard-scanner sbom`)
- Mermaid diagram support for single-node dependency paths in vulnerability reports
- PURL inspect endpoint now returns the associated component project

### Fixed

- IO_URING syscalls blocked by container seccomp profiles — `EIO_BACKEND` is now set to `posix` to avoid kernel-level syscall restrictions in hardened environments
- SBOM upload failed silently when a CycloneDX component had no name — the component's BOM-Ref is now used as a fallback name
- Dashboard URL in VEX reports always pointed to the main artifact instead of the correct artifact version
- GitLab auto-setup overwrote existing `.gitlab-ci.yml` files — the setup now performs a non-destructive YAML merge to preserve existing pipeline configuration
- Empty path to root component in GitLab vulnerability tickets
- Vulnerable components badge counted all dependency paths instead of unique CVE/component combinations, inflating the displayed count
- `merge-sbom` command did not include all root components in the resulting SBOM
- Bug in VulnDB CVE endpoint and package distribution endpoint

### Changed

- GitHub Actions workflows hardened: all action versions are now pinned and permissions follow the principle of least privilege
- Updated Go to 1.25.6, Trivy to v0.69.2, and all Go module dependencies

## [v1.0.0] - 2025-02-20

This is the first stable release of DevGuard. It marks the transition from the `v0.4.x` series and includes major architectural improvements, new scanning capabilities, and a significantly expanded API surface.

### Added

**SBOM & Dependency Graph**
- Complete rewrite of the SBOM dependency model using a graph-based approach — artifacts are now placed directly in the SBOM tree, replacing the former `artifact → component_dependencies` pivot table
- `keepOriginalSbomRootComponent` flag on assets: uploaded SBOMs can preserve their declared root component rather than being re-rooted automatically
- SBOM scoping to info sources: SBOMs can now be filtered and scoped based on their originating information source
- `merge-sbom` CLI command to combine multiple CycloneDX SBOMs into one
- External reference model and controller for managing external references on artifacts

**VEX & Vulnerability Management**
- VEX Rules: persistent rules for marking vulnerabilities as false positives or accepted risks, with path-pattern matching to scope rules to specific dependency paths
- VEX Download endpoint: export VEX documents directly from the API
- Vulnerability paths: full path tracking from the root component to each vulnerable dependency, exposed in all relevant API responses and tickets

**CSAF**
- Full CSAF 2.0 report generation: product tree, relationships, remediations, threat statements, and external URL references
- Dynamic analysis report type added to VEX/CSAF external references

**CI / Scanner**
- `kyverno2sarif` and `sarif2md` conversion utilities for infrastructure-as-code and policy scan results
- Automated attestation generation from the DevGuard scanner (cosign-signed)
- Configurable scanner timeout (`--timeout` flag); default increased to 300 seconds
- `--ignore-upstream-attestations` and `--ignore-external-references` flags for scanner CLI
- Red Hat ecosystem CVEs are now ingested and correlated

**Assets & Projects**
- Archived state for assets and projects from gitlab is preserved in DevGuard, allowing for historical data retention without cluttering active listings
- Pagination for asset and subproject listings with consistent default sort order (by name)
- Dependency proxy with VulnDB integration: proxy package registry requests through DevGuard for real-time vulnerability screening

**Platform**
- Documentation policy check: assets can be evaluated against a documentation standard policy
- Multi-organization RBAC middleware using Casbin v3
- Daemon pipeline: background processing of asset versions is now managed through a structured daemon pipeline
- Sitemap generation API endpoint for public vulnerability data
- Read-only root filesystem support in the DevGuard container image
- Improved API documentation (OpenAPI)

**Badges**
- CVSS badge width now adjusts dynamically based on the score string length
- New route to retrieve CVSS badges without authentication

### Changed

- Dependency injection refactored to use [Uber FX](https://github.com/uber-go/fx), improving modularity and testability
- VEX rule creation no longer emits spurious "detected" events
- License risk lifecycle handling improved; risks are no longer incorrectly copied between artifact versions
- Scanner result output refactored to group and deduplicate dependency vulnerabilities by PURL
- Upgraded Casbin to v3, updated all Go module dependencies

### Fixed

- Risk history being recalculated on every request even when no data changed
- Artifact deletion not cascading to associated dependency vulnerabilities
- Duplicate CVEs and threat elements in CSAF reports
- VEX reports shown under all artifact names instead of the correct one
- Version string appended to artifact name when qualifiers were already present in the PURL
- Components whose BOM-Ref and PURL differ not being found during path resolution
- CVSS query filter not applying correctly
- License risks being incorrectly marked as fixed when the license expression did not change
- GitLab ticket links using un-slugified refs
- Various database constraint and migration errors

[unstable]: https://github.com/l3montree-dev/devguard/compare/v1.4.2...main
[v1.4.2]: https://github.com/l3montree-dev/devguard/compare/v1.4.1...v1.4.2
[v1.4.1]: https://github.com/l3montree-dev/devguard/compare/v1.4.0...v1.4.1
[v1.4.0]: https://github.com/l3montree-dev/devguard/compare/v1.3.1...v1.4.0
[v1.3.1]: https://github.com/l3montree-dev/devguard/compare/v1.3.0...v1.3.1
[v1.3.0]: https://github.com/l3montree-dev/devguard/compare/v1.2.3...v1.3.0
[v1.2.3]: https://github.com/l3montree-dev/devguard/compare/v1.2.2...v1.2.3
[v1.2.2]: https://github.com/l3montree-dev/devguard/compare/v1.2.1...v1.2.2
[v1.2.1]: https://github.com/l3montree-dev/devguard/compare/v1.2.0...v1.2.1
[v1.2.0]: https://github.com/l3montree-dev/devguard/compare/v1.1.1...v1.2.0
[v1.1.1]: https://github.com/l3montree-dev/devguard/compare/v1.1.0...v1.1.1
[v1.1.0]: https://github.com/l3montree-dev/devguard/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/l3montree-dev/devguard/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/l3montree-dev/devguard/compare/v0.4.7...v1.0.0
