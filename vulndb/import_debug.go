// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package vulndb

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/dtos"
)

// showImportDebug logs per-row differences between what was just written to the DB (within tx)
// and what the gob archive in workingDir would produce. Call this after an integrity failure
// and before the fallback retry to see exactly which rows diverge.
//
// It works by re-populating the (now-empty) staging tables from the gob data, then running
// SQL comparisons between staging and the live tables — no Go-side hash computation needed.
// Only the gob files needed by the failing tables are loaded.
func showImportDebug(ctx context.Context, tx pgx.Tx, workingDir string, failingTables []string) {
	needsOSV := false
	needsExploits := false
	for _, t := range failingTables {
		switch t {
		case "cves", "cve_relationships", "affected_components", "cve_affected_component",
			"malicious_packages", "malicious_affected_components":
			needsOSV = true
		case "exploits":
			needsExploits = true
		}
	}

	if err := clearStagingTables(ctx, tx); err != nil {
		slog.Error("show-diff: could not clear staging tables", "err", err)
		return
	}

	if needsOSV {
		slog.Info("show-diff: loading osv.gob into staging tables")
		t := time.Now()
		osvEntries, err := readAllGobItems[OSVEntry](workingDir + "/osv.gob")
		if err != nil {
			slog.Error("show-diff: could not read osv.gob", "err", err)
			return
		}
		vulnRows := gobOSVToVulnFilterTransformer(time.Time{}, nil, nil)(osvEntries)
		malRows := gobOSVToMalFilterTransformer(time.Time{})(osvEntries)
		if err := insertCVEsBulk(ctx, tx, vulnRows.CVEs); err != nil {
			slog.Error("show-diff: could not insert CVEs into staging", "err", err)
			return
		}
		if err := insertCVERelationshipsBulk(ctx, tx, vulnRows.CVERelationships); err != nil {
			slog.Error("show-diff: could not insert cve_relationships into staging", "err", err)
			return
		}
		if err := insertAffectedComponentsBulk(ctx, tx, vulnRows.AffectedComponents); err != nil {
			slog.Error("show-diff: could not insert affected_components into staging", "err", err)
			return
		}
		if err := insertCVEAffectedComponentsBulk(ctx, tx, vulnRows.CVEAffectedComponents); err != nil {
			slog.Error("show-diff: could not insert cve_affected_component into staging", "err", err)
			return
		}
		if err := insertMaliciousPackagesBulk(ctx, tx, malRows.pkgs, malRows.comps); err != nil {
			slog.Error("show-diff: could not insert malicious packages into staging", "err", err)
			return
		}
		slog.Info("show-diff: osv staging ready",
			"cves", len(vulnRows.CVEs),
			"relationships", len(vulnRows.CVERelationships),
			"affected_components", len(vulnRows.AffectedComponents),
			"cve_affected_component", len(vulnRows.CVEAffectedComponents),
			"malicious_packages", len(malRows.pkgs),
			"took", time.Since(t),
		)

		// Apply EPSS and CISA KEV enrichment so the staging side matches what the
		// real import writes — without this, every enriched CVE looks like a mismatch.
		var epssData map[string]dtos.EPSS
		if err := readGobFile(workingDir+"/epss.gob", &epssData); err != nil {
			slog.Error("show-diff: could not read epss.gob", "err", err)
			return
		}
		if err := insertEPSSBulk(ctx, tx, epssData); err != nil {
			slog.Error("show-diff: could not apply EPSS to staging", "err", err)
			return
		}

		var kevEntries []CISAKEVEntry
		if err := readGobFile(workingDir+"/cisakev.gob", &kevEntries); err != nil {
			slog.Error("show-diff: could not read cisakev.gob", "err", err)
			return
		}
		if err := insertCISAKEVBulk(ctx, tx, kevEntries); err != nil {
			slog.Error("show-diff: could not apply CISA KEV to staging", "err", err)
			return
		}
		slog.Info("show-diff: EPSS and CISA KEV enrichment applied to staging", "epss_entries", len(epssData), "kev_entries", len(kevEntries))
	}

	if needsExploits {
		slog.Info("show-diff: loading exploits.gob into staging tables")
		t := time.Now()
		gobExploits, err := readAllGobItems[GobExploit](workingDir + "/exploits.gob")
		if err != nil {
			slog.Error("show-diff: could not read exploits.gob", "err", err)
			return
		}
		exploits := gobExploitFilterTransformer(time.Time{}, gobExploits)
		if err := insertExploitsBulk(ctx, tx, exploits); err != nil {
			slog.Error("show-diff: could not insert exploits into staging", "err", err)
			return
		}
		slog.Info("show-diff: exploits staging ready", "exploits", len(exploits), "took", time.Since(t))
	}

	for _, table := range failingTables {
		slog.Info("show-diff: analysing failing table", "table", table)
		var err error
		switch table {
		case "cves":
			err = diffTable(ctx, tx, diffSpec{
				live:        "cves",
				stage:       "cves_stage",
				liveID:      "cve",
				stageID:     "cve",
				joinCond:    "db.cve = gob.cve",
				contentCols: []string{"description", "cvss", "vector", "cisa_required_action", "cisa_vulnerability_name", "epss", "percentile"},
			})
		case "cve_relationships":
			err = diffTable(ctx, tx, diffSpec{
				live:     "cve_relationships",
				stage:    "cve_relationships_stage",
				liveID:   "source_cve || '|' || target_cve || '|' || relationship_type",
				stageID:  "source_cve || '|' || target_cve || '|' || relationship_type",
				joinCond: "db.source_cve = gob.source_cve AND db.target_cve = gob.target_cve AND db.relationship_type = gob.relationship_type",
			})
		case "affected_components":
			err = diffTable(ctx, tx, diffSpec{
				live:     "affected_components",
				stage:    "affected_components_stage",
				liveID:   "id::text",
				stageID:  "id::text",
				joinCond: "db.id = gob.id",
			})
		case "cve_affected_component":
			err = diffTable(ctx, tx, diffSpec{
				live:     "cve_affected_component",
				stage:    "cve_affected_component_stage",
				liveID:   "cve_id::text || '|' || affected_component_id::text",
				stageID:  "cve_id::text || '|' || affected_component_id::text",
				joinCond: "db.cve_id = gob.cve_id AND db.affected_component_id = gob.affected_component_id",
			})
		case "exploits":
			err = diffTable(ctx, tx, diffSpec{
				live:        "exploits",
				stage:       "exploits_stage",
				liveID:      "id",
				stageID:     "id",
				joinCond:    "db.id = gob.id",
				contentCols: []string{"cve_id", "source_url"},
			})
		case "malicious_packages":
			err = diffTable(ctx, tx, diffSpec{
				live:        "malicious_packages",
				stage:       "mal_pkgs_stage",
				liveID:      "id",
				stageID:     "id",
				joinCond:    "db.id = gob.id",
				contentCols: []string{"modified"},
				liveFilter:   "id NOT LIKE 'MAL-FAKE-TEST-%'",
				joinFilter:   "db.id NOT LIKE 'MAL-FAKE-TEST-%'",
			})
		case "malicious_affected_components":
			err = diffTable(ctx, tx, diffSpec{
				live:       "malicious_affected_components",
				stage:      "mal_comps_stage",
				liveID:     "id",
				stageID:    "id",
				joinCond:   "db.id = gob.id",
				liveFilter: "malicious_package_id NOT LIKE 'MAL-FAKE-TEST-%'",
			})
		default:
			slog.Info("show-diff: no diff handler for table", "table", table)
		}
		if err != nil {
			slog.Error("show-diff: diff failed", "table", table, "err", err)
		}
	}
}

type diffSpec struct {
	live        string
	stage       string
	liveID      string   // unaliased key expression (used in EXCEPT queries — no JOIN, no ambiguity)
	stageID     string   // unaliased key expression for the stage side
	joinCond    string   // fully aliased ON condition for content-diff JOIN: "db.x = gob.x"
	contentCols []string // columns to compare for content mismatches (unqualified; db./gob. added automatically)
	liveFilter  string   // WHERE fragment for single-table queries (no alias needed)
	joinFilter  string   // WHERE fragment for the JOIN query (must use db. alias, e.g. "db.id NOT LIKE '...'")
}

// diffTable runs a SQL-level diff between a live table and its freshly-populated staging
// counterpart, logging extra/missing/changed rows.
func diffTable(ctx context.Context, tx pgx.Tx, spec diffSpec) error {
	liveWhere := ""
	if spec.liveFilter != "" {
		liveWhere = "WHERE " + spec.liveFilter
	}

	var liveCount, stageCount int
	if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s %s`, spec.live, liveWhere)).Scan(&liveCount); err != nil {
		return fmt.Errorf("could not count live rows: %w", err)
	}
	if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, spec.stage)).Scan(&stageCount); err != nil {
		return fmt.Errorf("could not count stage rows: %w", err)
	}
	slog.Info("show-diff: row counts", "table", spec.live, "in_db", liveCount, "in_gob", stageCount)

	// Rows present in DB but missing from gob
	onlyInDBRows, err := tx.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM %s %s
		EXCEPT
		SELECT %s FROM %s
		LIMIT 20
	`, spec.liveID, spec.live, liveWhere, spec.stageID, spec.stage))
	if err != nil {
		return fmt.Errorf("could not query DB-only rows: %w", err)
	}
	defer onlyInDBRows.Close()
	for onlyInDBRows.Next() {
		var key string
		if err := onlyInDBRows.Scan(&key); err != nil {
			break
		}
		slog.Warn("show-diff: row in DB but not in gob", "table", spec.live, "key", key)
	}
	onlyInDBRows.Close()

	// Rows present in gob but missing from DB
	onlyInGobRows, err := tx.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM %s
		EXCEPT
		SELECT %s FROM %s %s
		LIMIT 20
	`, spec.stageID, spec.stage, spec.liveID, spec.live, liveWhere))
	if err != nil {
		return fmt.Errorf("could not query gob-only rows: %w", err)
	}
	defer onlyInGobRows.Close()
	for onlyInGobRows.Next() {
		var key string
		if err := onlyInGobRows.Scan(&key); err != nil {
			break
		}
		slog.Warn("show-diff: row in gob but not in DB", "table", spec.live, "key", key)
	}
	onlyInGobRows.Close()

	// Rows present on both sides but with different content
	if len(spec.contentCols) > 0 {
		contentConditions := ""
		for i, col := range spec.contentCols {
			if i > 0 {
				contentConditions += " OR "
			}
			contentConditions += fmt.Sprintf("db.%s IS DISTINCT FROM gob.%s", col, col)
		}
		joinWhere := contentConditions
		if spec.joinFilter != "" {
			joinWhere = spec.joinFilter + " AND (" + contentConditions + ")"
		}
		mismatchRows, err := tx.Query(ctx, fmt.Sprintf(`
			SELECT db.%s, row_to_json(db)::text, row_to_json(gob)::text
			FROM %s db
			JOIN %s gob ON %s
			WHERE %s
			LIMIT 20
		`, spec.liveID, spec.live, spec.stage, spec.joinCond, joinWhere))
		if err != nil {
			return fmt.Errorf("could not query content mismatches: %w", err)
		}
		defer mismatchRows.Close()
		for mismatchRows.Next() {
			var key, dbJSON, gobJSON string
			if err := mismatchRows.Scan(&key, &dbJSON, &gobJSON); err != nil {
				break
			}
			slog.Warn("show-diff: content mismatch", "table", spec.live, "key", key, "db_row", dbJSON, "gob_row", gobJSON)
		}
		mismatchRows.Close()
	}
	return nil
}
