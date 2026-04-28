# Changelog

All notable changes to this project will be documented in this file.

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
[@timbastin](https://github.com/timbastin), [@Hubtrick-Git](https://github.com/Hubtrick-Git), [@refoo0](https://github.com/refoo0), [@Dboy0ZDev](https://github.com/Dboy0ZDev), [@seb-kw](https://github.com/seb-kw), [@5byuri](https://github.com/5byuri), [@l3monKenji](https://github.com/l3monKenji)

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

[unstable]: https://github.com/l3montree-dev/devguard/compare/v1.2.3...main
[v1.2.3]: https://github.com/l3montree-dev/devguard/compare/v1.2.2...v1.2.3
[v1.2.2]: https://github.com/l3montree-dev/devguard/compare/v1.2.1...v1.2.2
[v1.2.1]: https://github.com/l3montree-dev/devguard/compare/v1.2.0...v1.2.1
[v1.2.0]: https://github.com/l3montree-dev/devguard/compare/v1.1.1...v1.2.0
[v1.1.1]: https://github.com/l3montree-dev/devguard/compare/v1.1.0...v1.1.1
[v1.1.0]: https://github.com/l3montree-dev/devguard/compare/v1.0.1...v1.1.0
[v1.0.1]: https://github.com/l3montree-dev/devguard/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/l3montree-dev/devguard/compare/v0.4.7...v1.0.0
