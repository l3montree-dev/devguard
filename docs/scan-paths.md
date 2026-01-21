# Scan Paths Documentation

This document provides a comprehensive overview of all scan entry points and their complete call stacks in DevGuard.

## Table of Contents

1. [HTTP Endpoints](#1-http-endpoints)
2. [Dependency Vulnerability Scan Flow](#2-dependency-vulnerability-scan-flow)
3. [SBOM File Upload Flow](#3-sbom-file-upload-flow)
4. [First-Party Vulnerability Scan Flow](#4-first-party-vulnerability-scan-flow)
5. [VEX Upload Flow](#5-vex-upload-flow)
6. [Async Operations (Fire and Forget)](#6-async-operations-fire-and-forget)
7. [Database Transaction Boundaries](#7-database-transaction-boundaries)
8. [Event Types and State Transitions](#8-event-types-and-state-transitions)
9. [Key Files Reference](#9-key-files-reference)

---

## 1. HTTP Endpoints

All scan endpoints are registered in `router/session_router.go` and `router/asset_router.go`:

| Endpoint | Method | Controller | Description |
|----------|--------|------------|-------------|
| `/scan/` | POST | `ScanController.ScanDependencyVulnFromProject` | Dependency vulnerability scan (JSON SBOM) |
| `/sbom-file` | POST | `ScanController.ScanSbomFile` | SBOM file upload (multipart, max 16MB) |
| `/sarif-scan/` | POST | `ScanController.FirstPartyVulnScan` | First-party vulnerability scan (SARIF format) |
| `/vex` | POST | `ScanController.UploadVEX` | VEX (Vulnerability Exploitability eXchange) upload |

### Common Headers

| Header | Description | Required |
|--------|-------------|----------|
| `X-Asset-Ref` | Asset version/branch name | No (defaults to "main") |
| `X-Artifact-Name` | Artifact identifier | No |
| `X-Tag` | Tag name | No |
| `X-Asset-Default-Branch` | Mark as default branch | No |
| `X-Origin` | Source identifier | No |
| `X-Scanner` | Scanner ID | Required for SARIF |

---

## 2. Dependency Vulnerability Scan Flow

**Endpoint:** `POST /scan/`

```
HTTP POST /scan/
  │
  ▼
ScanController.ScanDependencyVulnFromProject()
  │ [Decodes CycloneDX BOM from JSON body]
  │
  ▼
ScanController.DependencyVulnScan(c, bom)
  │
  ├─► normalize.SBOMGraphFromCycloneDX(bom, artifactName, origin)
  │   [Converts CycloneDX BOM to internal SBOMGraph format]
  │
  ├─► assetVersionRepository.FindOrCreate(...)
  │   [Creates or retrieves asset version record]
  │
  ├─► artifactService.SaveArtifact(artifact)
  │   [Saves artifact metadata to database]
  │
  ├─► Transaction BEGIN
  │   │
  │   ├─► assetVersionService.UpdateSBOM(tx, ...)
  │   │   │
  │   │   ├─► LoadFullSBOMGraph(assetVersion)
  │   │   │   [Loads all existing components]
  │   │   │
  │   │   ├─► wholeAssetGraph.MergeGraph(sbom)
  │   │   │   [Merges new SBOM with existing]
  │   │   │
  │   │   ├─► componentRepository.HandleStateDiff(tx, ...)
  │   │   │   [Updates component dependencies]
  │   │   │
  │   │   └─► [ASYNC] FireAndForget
  │   │       ├─► componentService.GetAndSaveLicenseInformation(...)
  │   │       └─► thirdPartyIntegration.HandleEvent(SBOMCreatedEvent)
  │   │
  │   └─► scanService.ScanNormalizedSBOM(tx, ...)
  │       │
  │       ├─► sbomScanner.Scan(normalizedBom)
  │       │   [Compares components against CVE database]
  │       │
  │       └─► assetVersionService.HandleScanResult(tx, ...)
  │           │
  │           ├─► statemachine.DiffScanResults(...)
  │           │   [Determines: NewlyDiscovered, Fixed, Unchanged]
  │           │
  │           ├─► dependencyVulnService.UserDetectedDependencyVulns(tx, ...)
  │           │   [Creates DETECTED events, saves vulns]
  │           │
  │           ├─► dependencyVulnService.UserFixedDependencyVulns(tx, ...)
  │           │   [Creates FIXED events, updates vulns]
  │           │
  │           └─► [ASYNC] thirdPartyIntegration.HandleEvent(DependencyVulnsDetectedEvent)
  │
  ├─► Transaction COMMIT
  │
  └─► [ASYNC] FireAndForget
      ├─► dependencyVulnService.SyncIssues(...)
      │   [Creates/updates GitHub/GitLab/Jira tickets]
      │
      └─► statisticsService.UpdateArtifactRiskAggregation(...)
          [Updates daily risk history]
```

---

## 3. SBOM File Upload Flow

**Endpoint:** `POST /sbom-file`

```
HTTP POST /sbom-file
  │
  ▼
ScanController.ScanSbomFile(c)
  │
  ├─► Parse multipart form (max 16MB)
  ├─► Decode CycloneDX BOM from file
  ├─► Set X-Origin header → "sbom-file-upload"
  │
  └─► ScanController.DependencyVulnScan(c, bom)
      [Same flow as Dependency Vulnerability Scan above]
```

---

## 4. First-Party Vulnerability Scan Flow

**Endpoint:** `POST /sarif-scan/`

```
HTTP POST /sarif-scan/
  │
  ▼
ScanController.FirstPartyVulnScan(ctx)
  │ [Decodes SARIF JSON scan result]
  │ [X-Scanner header required]
  │
  ├─► assetVersionRepository.FindOrCreate(...)
  │
  ├─► assetVersionService.HandleFirstPartyVulnResult(...)
  │   │
  │   ├─► Parse SARIF Rules and Results
  │   │   [Extracts vulnerability info from SARIF format]
  │   │
  │   ├─► firstPartyVulnRepository.ListUnfixedByAssetAndAssetVersionAndScanner(...)
  │   │   [Gets existing unfixed vulnerabilities]
  │   │
  │   ├─► utils.CompareSlices(existingVulns, vulns)
  │   │   [Determines: NewlyDiscovered, Fixed, Updated]
  │   │
  │   ├─► Transaction BEGIN
  │   │   │
  │   │   ├─► firstPartyVulnService.UserDetectedFirstPartyVulns(tx, ...)
  │   │   │   [Creates DETECTED events, saves vulns]
  │   │   │
  │   │   └─► firstPartyVulnService.UserFixedFirstPartyVulns(tx, ...)
  │   │       [Creates FIXED events, updates vulns]
  │   │
  │   ├─► Transaction COMMIT
  │   │
  │   └─► [ASYNC] thirdPartyIntegration.HandleEvent(FirstPartyVulnsDetectedEvent)
  │
  ├─► assetVersionRepository.Save(assetVersion)
  │   [Persists updated metadata]
  │
  └─► [ASYNC] FireAndForget
      └─► firstPartyVulnService.SyncIssues(...)
          [Updates existing tickets only]
```

---

## 5. VEX Upload Flow

**Endpoint:** `POST /vex`

```
HTTP POST /vex
  │
  ▼
ScanController.UploadVEX(ctx)
  │ [Decodes CycloneDX VEX BOM]
  │
  ├─► assetVersionRepository.FindOrCreate(...)
  │
  ├─► artifactService.SaveArtifact(artifact)
  │
  ├─► Extract external VEX references
  │   [Looks for ERTypeExploitabilityStatement URLs]
  │
  ├─► Build upstream BOMs list:
  │   │
  │   ├─► If BOM has components/vulnerabilities:
  │   │   └─► normalize.SBOMGraphFromCycloneDX(bom, ...)
  │   │
  │   └─► For each external URL:
  │       └─► artifactService.FetchBomsFromUpstream(...)
  │           ├─► CSAF provider URLs → csafService.GetVexFromCsafProvider(...)
  │           └─► Direct URLs → HTTP GET with validation
  │
  ├─► artifactService.SyncUpstreamBoms(...)
  │   │
  │   └─► For each BOM:
  │       │
  │       ├─► Transaction BEGIN
  │       │   │
  │       │   ├─► assetVersionService.UpdateSBOM(tx, ...)
  │       │   │
  │       │   ├─► assetVersionService.HandleScanResult(tx, ...)
  │       │   │
  │       │   └─► Apply VEX state transitions
  │       │       (Accepted, FalsePositive, Mitigated, etc.)
  │       │
  │       └─► Transaction COMMIT
  │
  └─► [ASYNC] FireAndForget
      ├─► dependencyVulnService.SyncIssues(...)
      └─► statisticsService.UpdateArtifactRiskAggregation(...)
```

---

## 6. Async Operations (Fire and Forget)

All async operations use `FireAndForgetSynchronizer`. In production, these run as goroutines. In tests with `SyncFireAndForgetSynchronizer`, they run synchronously.

### Issue/Ticket Management

```
dependencyVulnService.SyncIssues()
  │
  ├─► Check: ShouldCreateIssues(assetVersion)
  │   [Only for DefaultBranch or Tags]
  │
  ├─► Check: ShouldCreateThisIssue(asset, vuln)
  │   [Evaluates CVSSAutomaticTicketThreshold, RiskAutomaticTicketThreshold]
  │
  ├─► For vulns WITHOUT ticketID:
  │   └─► thirdPartyIntegration.CreateIssue(...)
  │       [Creates GitHub Issues / GitLab Issues / Jira tickets]
  │
  └─► For vulns WITH ticketID:
      └─► thirdPartyIntegration.UpdateIssue(...)
          [Updates existing tickets with state changes]
```

### License Information Fetching

```
componentService.GetAndSaveLicenseInformation()
  └─► Fetches and caches license data for all components
```

### Risk History Update

```
statisticsService.UpdateArtifactRiskAggregation()
  │
  └─► For each day from lastUpdate to now:
      ├─► statisticsRepository.TimeTravelDependencyVulnState(...)
      │   [Gets historical vulnerability state]
      │
      └─► Calculate risk aggregation (min/max/avg/sum by severity)
          └─► artifactRiskHistoryRepository.Save(history)
```

### Third-Party Integration Events

```
thirdPartyIntegration.HandleEvent(event)
  │
  ├─► SBOMCreatedEvent
  ├─► DependencyVulnsDetectedEvent (only for default branch or tags)
  └─► FirstPartyVulnsDetectedEvent (only for default branch or tags)
      │
      └─► Provider-specific handlers:
          ├─► GitHubIntegration.HandleEvent()
          ├─► GitLabIntegration.HandleEvent()
          ├─► JiraIntegration.HandleEvent()
          └─► WebhookIntegration.HandleEvent()
```

---

## 7. Database Transaction Boundaries

### Dependency Scan Main Transaction

```sql
BEGIN TRANSACTION
  -- SBOM Update
  UPDATE components, component_dependencies (via HandleStateDiff)

  -- Vulnerability Detection
  INSERT INTO dependency_vulns (new vulnerabilities)
  INSERT INTO vuln_events (detection events)

  -- Fixed Vulnerabilities
  UPDATE dependency_vulns (state = FIXED)
  INSERT INTO vuln_events (fixed events)

  -- Depth Updates
  UPDATE dependency_vulns (component_depth)
COMMIT TRANSACTION

-- AFTER COMMIT (async):
-- Issue creation/updates
-- Statistics updates
```

### First-Party Vulnerability Transaction

```sql
BEGIN TRANSACTION
  INSERT INTO first_party_vulns (new vulnerabilities)
  INSERT INTO vuln_events (detection/fix events)
  UPDATE first_party_vulns (snippet updates)
COMMIT TRANSACTION
```

> **Note:** The async operations (`SyncIssues`, `UpdateArtifactRiskAggregation`) run AFTER the transaction commits. In tests using `SyncFireAndForgetSynchronizer`, these run synchronously which can cause deadlocks if the transaction isn't committed first.

---

## 8. Event Types and State Transitions

### Vulnerability Event Types

| Event Type | Description |
|------------|-------------|
| `DETECTED` | New vulnerability found |
| `FIXED` | Vulnerability no longer present |
| `REOPENED` | Previously fixed vulnerability reappeared |
| `ACCEPTED` | User acknowledged and accepted the risk |
| `FALSE_POSITIVE` | User marked as incorrect detection |
| `MITIGATE` | User documented mitigation |
| `MARKED_FOR_TRANSFER` | User transferred responsibility |
| `COMMENT` | User added annotation |
| `RAW_RISK_ASSESSMENT_UPDATED` | System recalculated risk |

### State Transitions

```
OPEN ──────► FIXED (automatic from scan)
  │
  ├────────► ACCEPTED (user action)
  ├────────► FALSE_POSITIVE (user action)
  └────────► MITIGATED (user action)

FIXED ─────► REOPENED (automatic from scan)

ANY ───────► COMMENT (user action)
```

---

## 9. Key Files Reference

### Controllers

| File | Description |
|------|-------------|
| `controllers/scan_controller.go` | All scan HTTP endpoints |
| `controllers/asset_version_controller.go` | Asset version management |

### Services

| File | Description |
|------|-------------|
| `services/scan_service.go` | Scan orchestration |
| `services/asset_version_service.go` | SBOM updates, scan result handling |
| `services/dependency_vuln_service.go` | Dependency vulnerability management |
| `services/first_party_vuln_service.go` | First-party vulnerability management |
| `services/artifact_service.go` | Artifact and upstream BOM management |
| `services/statistics_service.go` | Risk aggregation and history |

### Repositories

| File | Description |
|------|-------------|
| `database/repositories/dependency_vuln_repository.go` | Dependency vuln persistence |
| `database/repositories/first_party_vuln_repository.go` | First-party vuln persistence |
| `database/repositories/component_repository.go` | Component persistence |

### Utilities

| File | Description |
|------|-------------|
| `normalize/sbom_graph.go` | SBOM merging & transformation |
| `normalize/purl.go` | Package URL handling |
| `vulndb/scan/sbom_scanner.go` | CVE scanning logic |
| `statemachine/vuln_statemachine.go` | Vulnerability state management |

### Integration Events

| File | Description |
|------|-------------|
| `shared/thirdparty_integration.go` | Integration interface |
| `shared/thirdparty_integration_events.go` | Event definitions |
| `integrations/thirdparty_integration.go` | Event dispatcher |

---

## Architecture Notes

### Known Issue: Test Deadlocks

When using `SyncFireAndForgetSynchronizer` in tests, async operations run synchronously. This can cause deadlocks when:

1. A transaction is still open
2. `SyncIssues` is called synchronously
3. `SyncIssues` tries to access the database

**Solution options:**
1. Ensure transaction commits before async operations
2. Use post-commit hooks pattern
3. Pass transaction to async operations
4. Use outbox pattern for event processing
