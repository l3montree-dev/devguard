# vulndb

The `vulndb` package manages the lifecycle of DevGuard's vulnerability database. It builds the database from upstream sources (OSV, EPSS, CISA KEV, exploit data, and malicious packages), packages it into a distributable archive, and imports it — either incrementally or in full — into a PostgreSQL database.

---

## Overview

The package has two primary entry points:

- **`ExportRC`** — fetches all upstream vulnerability data, writes it to the database, serializes snapshots to gob files, and packages everything into a `vulndb.tar.zst` archive that is pushed to an OCI registry.
- **`ImportRC`** — pulls the archive from the OCI registry and imports its contents into a target database, with support for incremental and full import modes.

---

## Export (`ExportRC`)

### OSV ingestion

OSV vulnerability data is downloaded in parallel for 13 ecosystems from:

```
https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip
```

Each zip contains one JSON file per vulnerability entry in OSV format.

Zip contents are processed through a pool of workers. To maximize write throughput, database indexes are dropped before bulk insertion and rebuilt afterwards using staging tables.

### Additional data sources

After OSV ingestion completes, the following are fetched in parallel:

- **EPSS** — exploit prediction scores.
- **CISA KEV** — Known Exploited Vulnerabilities catalog.
- **Exploits** — exploit metadata from ExploitDB and GitHub.

### Cleanup

After all data is written, cleanup jobs remove:
- Orphaned CVEs (no longer referenced by any upstream source).
- Orphaned affected components (no longer linked to any CVE).

### Output artifacts

The following files are written before packaging:

| File | Contents |
|---|---|
| `osv.gob` | Serialized OSV vulnerability entries |
| `epss.gob` | EPSS scores |
| `cisakev.gob` | CISA KEV entries |
| `exploits.gob` | Exploit metadata |
| `integrity_checks.json` | Per-table checksums used to validate imports |

All artifacts are bundled into `vulndb.tar.zst` and pushed to an OCI registry.

---

## Import (`ImportRC`)

### Modes

**Incremental (default)**

Only processes CVE entries that are new or have changed since the last import watermark. After import, integrity checks run and any failing tables are re-imported in full automatically.

**Full (`--full`)**

Truncates all relevant tables and reimports everything from scratch. Use this when the database needs to be rebuilt from a clean state.

---

## The Modified Timestamp Problem

This is the most important correctness concern in the incremental import path.

OSV sets the `modified` field on a vulnerability to when the bug was **filed** — for example, when it was first reported to OSS-Fuzz. This timestamp is not when the entry was **published** to the OSV GCS bucket, which can lag by many hours.

**Concrete example:**

- `OSV-2026-717` has `modified: 00:11Z` — set when the bug was filed with OSS-Fuzz.
- The GCS object for the individual JSON file was only created at `17:10Z`.
- However, the `all.zip` downloaded at `15:15Z` already contained this entry.
- The last import watermark was `05:10Z`.

The `modified` field inside the JSON and the `modified_id.csv` timestamps are always identical — OSV derives both from the same source. The zip file's internal mtime is also set to the same value. There is no timestamp in the zip that reflects when the entry was *published*, only when the underlying bug was filed.

The old incremental filter (`modified > lastImportTime`) would skip this entry because `00:11Z < 05:10Z`, even though the entry was genuinely new to the database. It would remain missing and cause integrity check failures on every subsequent import.

### The fix

At the start of every incremental import, all existing CVE IDs are loaded from the database:

```sql
SELECT id FROM cves
```

The filter logic then becomes:

- **CVE ID not in DB** — import unconditionally, regardless of `modified` timestamp. The entry is new and was never seen before.
- **CVE ID already in DB** — apply the normal `modified > lastImportTime` filter. Skip entries that have not changed since the last import.

This means the `modified` timestamp is only used to skip *updates* to existing entries, never to skip *new* entries.

---

## Integrity Checks

After every import, checksums are computed per table and compared against the values in `integrity_checks.json` (written during export). If any table's checksum does not match:

1. Only the failing tables are identified.
2. A targeted full import is run for those tables only.
3. Checksums are recomputed and verified.

This avoids silently accepting a partially corrupted import.

---

## CISA KEV Enrichment

CISA KEV data is applied on top of imported OSV CVEs as a post-processing step. Before applying new KEV data, all CISA-related fields are reset to `NULL` across all CVEs. This ensures that CVEs which have been removed from the KEV catalog do not retain stale KEV metadata from a previous import.

---

## Affected Component Deduplication

During incremental import, two in-memory maps are maintained to efficiently detect and generate deletion rows when a CVE's affected components change:

- `componentToCVEs`: `affectedComponentID → []cveID` — tracks which CVEs reference each component.
- `cveToComponents`: `cveID → []affectedComponentID` — reverse map for O(k) lookup per CVE.

When a CVE is updated and its component set changes, the reverse map is used to identify removed components in O(k) time (where k is the number of components for that CVE), rather than scanning the full components table.

---

## Cleanup After Incremental Import

When pivot rows (CVE ↔ affected component links) are deleted during an incremental import, `runScopedCleanUpJobs` is called to remove any resulting orphans. Importantly, cleanup is **scoped to only the affected IDs** — it does not perform a full table scan. This keeps incremental import performance predictable even on large databases.
