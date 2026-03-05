# Changelog

All notable changes to this project will be documented in this file.

## [unstable]

## General notes

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release notes MUST identify every publicly known run-time vulnerability fixed in this release that already had a CVE assignment or similar when the release was created.

You can find the public key for verifying the image and SBOM signatures here: [cosign.pub](https://github.com/l3montree-dev/devguard/blob/main/cosign.pub)

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

[unstable]: https://github.com/l3montree-dev/devguard/compare/v1.0.1...main
[v1.0.1]: https://github.com/l3montree-dev/devguard/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/l3montree-dev/devguard/compare/v0.4.7...v1.0.0
