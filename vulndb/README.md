# vulndb

The `vulndb` package manages the lifecycle of DevGuard's vulnerability database. It builds the database from upstream sources (OSV, EPSS, CISA KEV, exploit data, and malicious packages), packages it into a distributable archive, and imports it into a PostgreSQL database using an EXCEPT-based sync that is fully idempotent.

---

## Overview

The package has two primary entry points:

- **`ExportRC`** — fetches all upstream vulnerability data, writes it to the database, serializes snapshots to gob files, and packages everything into a `vulndb.tar.zst` archive that is pushed to an OCI registry.
- **`ImportRC`** — pulls the archive from the OCI registry and imports its contents into a target database, with support for streaming (incremental) and bulk (full) processing modes.

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
- **Exploits** — exploit metadata from ExploitDB and GitHub. Only exploits referencing a CVE present in the database are retained.

Before computing the integrity checksums, stale exploits (present in the database from a prior export but absent from the current fetch) are deleted so the live table exactly matches the gob.

### Output artifacts

The following files are written before packaging:

| File | Contents |
|---|---|
| `osv.gob` | Serialized OSV vulnerability entries |
| `epss.gob` | EPSS scores |
| `cisakev.gob` | CISA KEV entries |
| `exploits.gob` | Exploit metadata |
| `integrity_checks.json` | Per-table row counts and checksums used to validate imports |

All artifacts are bundled into `vulndb.tar.zst` and pushed to an OCI registry.

---

## Import (`ImportRC`)

### Processing modes

**Streaming (default)**

Reads gob files in batches and streams them to staging tables. After all data is staged, `syncAllTables` applies an EXCEPT-based diff to the live tables (see below). Uses less memory than bulk mode.

**Bulk (`--bulk`)**

Loads all gob data into memory at once, then truncates the live tables and does a direct INSERT from staging. Faster for a clean initial import but requires ~2–3 GB of RAM.

### EXCEPT-based sync (`syncAllTables`)

The incremental sync is implemented as a three-step SQL operation per table, handled by the generic `syncTable` function:

1. **DELETE** rows present in the live table but absent from staging (`EXCEPT`).
2. **INSERT** rows present in staging but absent from the live table (`EXCEPT`).
3. **UPDATE** rows where the key exists on both sides but the `content_hash` (or equivalent change-detection column) differs.

This approach is fully idempotent — running the same import twice produces the same result. There is no dependency on a last-import watermark for correctness.

### CVE change detection

CVEs use a stable primary key (`id = hash(cve_string)`) for FK stability, plus a separate `content_hash` column that covers the OSV-sourced fields (`description`, `cvss`, `vector`). EPSS and CISA KEV are intentionally excluded from `content_hash` — they are applied as separate `UPDATE` steps after the sync and their changes do not trigger a delete+reinsert of the CVE or its related rows.

### EPSS and CISA KEV enrichment

After `syncAllTables` completes, EPSS scores and CISA KEV metadata are applied directly to the live `cves` table via bulk UPDATE. Before applying CISA KEV data, all CISA-related fields are reset to `NULL` so that CVEs removed from the KEV catalog do not retain stale metadata.

---

## Integrity Checks

After every import, per-table row counts and checksums are computed and compared against the values in `integrity_checks.json` (written during export). A mismatch causes the import transaction to be rolled back and an error to be returned. Because the sync is deterministic, there is no retry — a mismatch indicates a real inconsistency between the gob data and the integrity file.

---

## Affected Component Deduplication

During streaming, each batch transformer shares a `componentToCVEs` map (`affectedComponentID → []cveID`) across calls. This ensures that:

- Each unique `affected_components` row is only staged once across all batches.
- Each `cve_affected_component` pivot row is only staged once even if the same CVE→component relationship appears in multiple OSV entries.
