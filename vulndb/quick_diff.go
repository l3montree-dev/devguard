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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
)

// QuickDiff is a pre-computed incremental patch from one vulndb version to the next.
// When the importer's current DB version matches FromVersion the patch can be applied
// directly — no staging tables, no EXCEPT queries over millions of rows.
type QuickDiff struct {
	FromVersion time.Time

	CVEsDeleted  []int64
	CVEsInserted []quickDiffCVE // rows whose id is new
	CVEsUpdated  []quickDiffCVE // rows whose content_hash changed

	RelationshipsDeleted  []quickDiffRelKey
	RelationshipsInserted []quickDiffRelKey

	AffectedComponentsDeleted  []int64
	AffectedComponentsInserted []quickDiffAC

	PivotDeleted  []quickDiffPivot
	PivotInserted []quickDiffPivot

	ExploitsDeleted  []string
	ExploitsInserted []GobExploit
	ExploitsUpdated  []GobExploit

	MalPkgsDeleted  []string
	MalPkgsInserted []models.MaliciousPackage
	MalPkgsUpdated  []models.MaliciousPackage

	MalCompsDeleted  []string
	MalCompsInserted []GobMaliciousComponent
}

type quickDiffCVE struct {
	ID                    int64
	ContentHash           int64
	CVE                   string
	DatePublished         time.Time
	DateLastModified      time.Time
	Description           string
	CVSS                  float32
	References            string
	CISAExploitAdd        *string // "YYYY-MM-DD" or nil
	CISAActionDue         *string
	CISARequiredAction    string
	CISAVulnerabilityName string
	EPSS                  *float64
	Percentile            *float32
	Vector                string
}

type quickDiffRelKey struct {
	SourceCVE        string
	TargetCVE        string
	RelationshipType string
}

type quickDiffAC struct {
	ID                int64
	Purl              string
	Ecosystem         string
	Version           *string
	SemverIntroduced  *string
	SemverFixed       *string
	VersionIntroduced *string
	VersionFixed      *string
}

type quickDiffPivot struct {
	CveID               int64
	AffectedComponentID int64
}

// snapshotPrevState creates lightweight temp tables capturing the current DB state
// before the export truncates and reloads everything. Call this inside the export
// transaction before any TRUNCATE.
func snapshotPrevState(ctx context.Context, tx pgx.Tx) error {
	t := time.Now()
	queries := []string{
		`CREATE TEMP TABLE _snap_cves      AS SELECT id, content_hash FROM cves`,
		`CREATE TEMP TABLE _snap_rel       AS SELECT source_cve, target_cve, relationship_type FROM cve_relationships`,
		`CREATE TEMP TABLE _snap_ac        AS SELECT id FROM affected_components`,
		`CREATE TEMP TABLE _snap_pivot     AS SELECT cve_id, affected_component_id FROM cve_affected_component`,
		`CREATE TEMP TABLE _snap_exploits  AS SELECT id, updated FROM exploits`,
		`CREATE TEMP TABLE _snap_mal_pkgs  AS SELECT id, modified FROM malicious_packages`,
		`CREATE TEMP TABLE _snap_mal_comps AS SELECT id FROM malicious_affected_components`,
	}
	for _, q := range queries {
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("snapshotPrevState: %w", err)
		}
	}
	slog.Info("quick-diff: prev state snapshot created", "took", time.Since(t))
	return nil
}

// computeQuickDiff runs SQL diffs between the snapshot (prev state) and the current
// live tables (new state) and collects the results into a QuickDiff. Call this after
// the new data has been fully loaded into the live tables and EPSS/CISA applied.
func computeQuickDiff(ctx context.Context, tx pgx.Tx, fromVersion time.Time) (*QuickDiff, error) {
	diff := &QuickDiff{FromVersion: fromVersion}
	t := time.Now()

	// --- CVEs ---
	rows, err := tx.Query(ctx, `SELECT id FROM _snap_cves EXCEPT SELECT id FROM cves`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff cves deleted: %w", err)
	}
	diff.CVEsDeleted, err = collectScalars[int64](rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT c.id, c.content_hash, c.cve, c.date_published, c.date_last_modified,
		       c.description, c.cvss, c."references", c.cisa_required_action,
		       c.cisa_vulnerability_name, c.epss, c.percentile, c.vector,
		       to_char(c.cisa_exploit_add, 'YYYY-MM-DD'),
		       to_char(c.cisa_action_due,  'YYYY-MM-DD')
		FROM cves c
		WHERE NOT EXISTS (SELECT 1 FROM _snap_cves s WHERE s.id = c.id)
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff cves inserted: %w", err)
	}
	diff.CVEsInserted, err = collectCVERows(rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT c.id, c.content_hash, c.cve, c.date_published, c.date_last_modified,
		       c.description, c.cvss, c."references", c.cisa_required_action,
		       c.cisa_vulnerability_name, c.epss, c.percentile, c.vector,
		       to_char(c.cisa_exploit_add, 'YYYY-MM-DD'),
		       to_char(c.cisa_action_due,  'YYYY-MM-DD')
		FROM cves c
		JOIN _snap_cves s ON s.id = c.id
		WHERE s.content_hash != c.content_hash
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff cves updated: %w", err)
	}
	diff.CVEsUpdated, err = collectCVERows(rows)
	if err != nil {
		return nil, err
	}

	// --- CVE relationships ---
	rows, err = tx.Query(ctx, `
		SELECT source_cve, target_cve, relationship_type FROM _snap_rel
		EXCEPT SELECT source_cve, target_cve, relationship_type FROM cve_relationships`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff relationships deleted: %w", err)
	}
	diff.RelationshipsDeleted, err = collectRelKeys(rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT source_cve, target_cve, relationship_type FROM cve_relationships
		EXCEPT SELECT source_cve, target_cve, relationship_type FROM _snap_rel`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff relationships inserted: %w", err)
	}
	diff.RelationshipsInserted, err = collectRelKeys(rows)
	if err != nil {
		return nil, err
	}

	// --- Affected components ---
	rows, err = tx.Query(ctx, `SELECT id FROM _snap_ac EXCEPT SELECT id FROM affected_components`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff ac deleted: %w", err)
	}
	diff.AffectedComponentsDeleted, err = collectScalars[int64](rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT a.id, a.purl, a.ecosystem, a.version::text,
		       a.semver_introduced::text, a.semver_fixed::text,
		       a.version_introduced, a.version_fixed
		FROM affected_components a
		WHERE NOT EXISTS (SELECT 1 FROM _snap_ac s WHERE s.id = a.id)
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff ac inserted: %w", err)
	}
	diff.AffectedComponentsInserted, err = collectACRows(rows)
	if err != nil {
		return nil, err
	}

	// --- cve_affected_component pivot ---
	rows, err = tx.Query(ctx, `
		SELECT cve_id, affected_component_id FROM _snap_pivot
		EXCEPT SELECT cve_id, affected_component_id FROM cve_affected_component`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff pivot deleted: %w", err)
	}
	diff.PivotDeleted, err = collectPivotRows(rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT cve_id, affected_component_id FROM cve_affected_component
		EXCEPT SELECT cve_id, affected_component_id FROM _snap_pivot`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff pivot inserted: %w", err)
	}
	diff.PivotInserted, err = collectPivotRows(rows)
	if err != nil {
		return nil, err
	}

	// --- Exploits ---
	rows, err = tx.Query(ctx, `SELECT id FROM _snap_exploits EXCEPT SELECT id FROM exploits`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff exploits deleted: %w", err)
	}
	diff.ExploitsDeleted, err = collectScalars[string](rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT e.id, e.published, e.updated, e.author, e.type, e.verified,
		       e.source_url, e.description, e.cve_id, e.tags,
		       e.forks, e.watchers, e.subscribers, e.stars
		FROM exploits e
		WHERE NOT EXISTS (SELECT 1 FROM _snap_exploits s WHERE s.id = e.id)
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff exploits inserted: %w", err)
	}
	diff.ExploitsInserted, err = collectExploitRows(rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT e.id, e.published, e.updated, e.author, e.type, e.verified,
		       e.source_url, e.description, e.cve_id, e.tags,
		       e.forks, e.watchers, e.subscribers, e.stars
		FROM exploits e
		JOIN _snap_exploits s ON s.id = e.id
		WHERE s.updated IS DISTINCT FROM e.updated
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff exploits updated: %w", err)
	}
	diff.ExploitsUpdated, err = collectExploitRows(rows)
	if err != nil {
		return nil, err
	}

	// --- Malicious packages ---
	rows, err = tx.Query(ctx, `SELECT id FROM _snap_mal_pkgs EXCEPT SELECT id FROM malicious_packages`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff mal_pkgs deleted: %w", err)
	}
	diff.MalPkgsDeleted, err = collectScalars[string](rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT m.id, m.summary, m.details, m.published, m.modified
		FROM malicious_packages m
		WHERE NOT EXISTS (SELECT 1 FROM _snap_mal_pkgs s WHERE s.id = m.id)
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff mal_pkgs inserted: %w", err)
	}
	diff.MalPkgsInserted, err = collectMalPkgRows(rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT m.id, m.summary, m.details, m.published, m.modified
		FROM malicious_packages m
		JOIN _snap_mal_pkgs s ON s.id = m.id
		WHERE s.modified IS DISTINCT FROM m.modified
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff mal_pkgs updated: %w", err)
	}
	diff.MalPkgsUpdated, err = collectMalPkgRows(rows)
	if err != nil {
		return nil, err
	}

	// --- Malicious affected components ---
	rows, err = tx.Query(ctx, `SELECT id FROM _snap_mal_comps EXCEPT SELECT id FROM malicious_affected_components`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff mal_comps deleted: %w", err)
	}
	diff.MalCompsDeleted, err = collectScalars[string](rows)
	if err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
		SELECT mc.id, mc.malicious_package_id, mc.purl, mc.ecosystem, mc.version::text,
		       mc.semver_introduced::text, mc.semver_fixed::text,
		       mc.version_introduced, mc.version_fixed
		FROM malicious_affected_components mc
		WHERE NOT EXISTS (SELECT 1 FROM _snap_mal_comps s WHERE s.id = mc.id)
	`)
	if err != nil {
		return nil, fmt.Errorf("quick-diff mal_comps inserted: %w", err)
	}
	diff.MalCompsInserted, err = collectMalCompRows(rows)
	if err != nil {
		return nil, err
	}

	slog.Info("quick-diff: diff computed",
		"cves_deleted", len(diff.CVEsDeleted),
		"cves_inserted", len(diff.CVEsInserted),
		"cves_updated", len(diff.CVEsUpdated),
		"relationships_deleted", len(diff.RelationshipsDeleted),
		"relationships_inserted", len(diff.RelationshipsInserted),
		"ac_deleted", len(diff.AffectedComponentsDeleted),
		"ac_inserted", len(diff.AffectedComponentsInserted),
		"pivot_deleted", len(diff.PivotDeleted),
		"pivot_inserted", len(diff.PivotInserted),
		"exploits_deleted", len(diff.ExploitsDeleted),
		"exploits_inserted", len(diff.ExploitsInserted),
		"exploits_updated", len(diff.ExploitsUpdated),
		"mal_pkgs_deleted", len(diff.MalPkgsDeleted),
		"mal_pkgs_inserted", len(diff.MalPkgsInserted),
		"mal_pkgs_updated", len(diff.MalPkgsUpdated),
		"mal_comps_deleted", len(diff.MalCompsDeleted),
		"mal_comps_inserted", len(diff.MalCompsInserted),
		"took", time.Since(t),
	)
	return diff, nil
}

// computeDiffFromQuickDiff materialises a QuickDiff struct into the same
// _diff_del_*, _diff_ins_*, _diff_upd_* temp tables that computeDiffFromStage
// produces. After this call, applyDiff works identically for both paths.
func computeDiffFromQuickDiff(ctx context.Context, tx pgx.Tx, diff *QuickDiff) error {
	// Helper: create a temp table with the same schema as a live table (no rows).
	createLike := func(tmp, live, cols string) error {
		_, err := tx.Exec(ctx, fmt.Sprintf(
			`CREATE TEMP TABLE %s ON COMMIT DROP AS SELECT %s FROM %s WHERE false`,
			tmp, cols, live,
		))
		return err
	}

	// --- cves ---
	if err := createLike("_diff_del_cves", "cves", "id"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_cves: %w", err)
	}
	if err := copyIDs(ctx, tx, "_diff_del_cves", "id", diff.CVEsDeleted); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_cves: %w", err)
	}

	cvePlain := []string{"id", "content_hash", "cve", "date_published", "date_last_modified", "description", "cvss", "references", "cisa_exploit_add", "cisa_action_due", "cisa_required_action", "cisa_vulnerability_name", "epss", "percentile", "vector"}
	if err := createLike("_diff_ins_cves", "cves", `id, content_hash, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector`); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_cves: %w", err)
	}
	if len(diff.CVEsInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_cves"}, cvePlain, pgx.CopyFromSlice(len(diff.CVEsInserted), func(i int) ([]interface{}, error) {
			c := diff.CVEsInserted[i]
			return []interface{}{c.ID, c.ContentHash, c.CVE, c.DatePublished, c.DateLastModified, c.Description, c.CVSS, c.References, c.CISAExploitAdd, c.CISAActionDue, c.CISARequiredAction, c.CISAVulnerabilityName, c.EPSS, c.Percentile, c.Vector}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_cves: %w", err)
		}
	}
	if err := createLike("_diff_upd_cves", "cves", `id, content_hash, cve, date_published, date_last_modified, description, cvss, "references", cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name, epss, percentile, vector`); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_upd_cves: %w", err)
	}
	if len(diff.CVEsUpdated) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_upd_cves"}, cvePlain, pgx.CopyFromSlice(len(diff.CVEsUpdated), func(i int) ([]interface{}, error) {
			c := diff.CVEsUpdated[i]
			return []interface{}{c.ID, c.ContentHash, c.CVE, c.DatePublished, c.DateLastModified, c.Description, c.CVSS, c.References, c.CISAExploitAdd, c.CISAActionDue, c.CISARequiredAction, c.CISAVulnerabilityName, c.EPSS, c.Percentile, c.Vector}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_upd_cves: %w", err)
		}
	}

	// --- cve_relationships ---
	if err := createLike("_diff_del_cve_relationships", "cve_relationships", "target_cve, source_cve, relationship_type"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_cve_relationships: %w", err)
	}
	if len(diff.RelationshipsDeleted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_del_cve_relationships"}, []string{"source_cve", "target_cve", "relationship_type"}, pgx.CopyFromSlice(len(diff.RelationshipsDeleted), func(i int) ([]interface{}, error) {
			r := diff.RelationshipsDeleted[i]
			return []interface{}{r.SourceCVE, r.TargetCVE, r.RelationshipType}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_cve_relationships: %w", err)
		}
	}
	if err := createLike("_diff_ins_cve_relationships", "cve_relationships", "target_cve, source_cve, relationship_type"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_cve_relationships: %w", err)
	}
	if len(diff.RelationshipsInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_cve_relationships"}, []string{"source_cve", "target_cve", "relationship_type"}, pgx.CopyFromSlice(len(diff.RelationshipsInserted), func(i int) ([]interface{}, error) {
			r := diff.RelationshipsInserted[i]
			return []interface{}{r.SourceCVE, r.TargetCVE, r.RelationshipType}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_cve_relationships: %w", err)
		}
	}

	// --- affected_components ---
	acCols := []string{"id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	if err := createLike("_diff_del_affected_components", "affected_components", "id"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_affected_components: %w", err)
	}
	if err := copyIDs(ctx, tx, "_diff_del_affected_components", "id", diff.AffectedComponentsDeleted); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_affected_components: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _diff_ins_affected_components ON COMMIT DROP AS
		SELECT id, purl, ecosystem, version::text, semver_introduced::text, semver_fixed::text, version_introduced, version_fixed
		FROM affected_components WHERE false`); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_affected_components: %w", err)
	}
	if len(diff.AffectedComponentsInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_affected_components"}, acCols, pgx.CopyFromSlice(len(diff.AffectedComponentsInserted), func(i int) ([]interface{}, error) {
			a := diff.AffectedComponentsInserted[i]
			return []interface{}{a.ID, a.Purl, a.Ecosystem, a.Version, a.SemverIntroduced, a.SemverFixed, a.VersionIntroduced, a.VersionFixed}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_affected_components: %w", err)
		}
	}

	// --- cve_affected_component ---
	pivotCols := []string{"affected_component_id", "cve_id"}
	if err := createLike("_diff_del_cve_affected_component", "cve_affected_component", strings.Join(pivotCols, ", ")); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_cve_affected_component: %w", err)
	}
	if len(diff.PivotDeleted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_del_cve_affected_component"}, []string{"cve_id", "affected_component_id"}, pgx.CopyFromSlice(len(diff.PivotDeleted), func(i int) ([]interface{}, error) {
			p := diff.PivotDeleted[i]
			return []interface{}{p.CveID, p.AffectedComponentID}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_cve_affected_component: %w", err)
		}
	}
	if err := createLike("_diff_ins_cve_affected_component", "cve_affected_component", strings.Join(pivotCols, ", ")); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_cve_affected_component: %w", err)
	}
	if len(diff.PivotInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_cve_affected_component"}, []string{"cve_id", "affected_component_id"}, pgx.CopyFromSlice(len(diff.PivotInserted), func(i int) ([]interface{}, error) {
			p := diff.PivotInserted[i]
			return []interface{}{p.CveID, p.AffectedComponentID}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_cve_affected_component: %w", err)
		}
	}

	// --- exploits ---
	exploitCols := []string{"id", "published", "updated", "author", "type", "verified", "source_url", "description", "cve_id", "tags", "forks", "watchers", "subscribers", "stars"}
	if err := createLike("_diff_del_exploits", "exploits", "id"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_exploits: %w", err)
	}
	if err := copyIDs(ctx, tx, "_diff_del_exploits", "id", diff.ExploitsDeleted); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_exploits: %w", err)
	}
	if err := createLike("_diff_ins_exploits", "exploits", strings.Join(exploitCols, ", ")); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_exploits: %w", err)
	}
	if len(diff.ExploitsInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_exploits"}, exploitCols, pgx.CopyFromSlice(len(diff.ExploitsInserted), func(i int) ([]interface{}, error) {
			m := gobExploitToModel(diff.ExploitsInserted[i])
			return []interface{}{m.ID, m.Published, m.Updated, m.Author, m.Type, m.Verified, m.SourceURL, m.Description, m.CVEID, m.Tags, m.Forks, m.Watchers, m.Subscribers, m.Stars}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_exploits: %w", err)
		}
	}
	if err := createLike("_diff_upd_exploits", "exploits", strings.Join(exploitCols, ", ")); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_upd_exploits: %w", err)
	}
	if len(diff.ExploitsUpdated) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_upd_exploits"}, exploitCols, pgx.CopyFromSlice(len(diff.ExploitsUpdated), func(i int) ([]interface{}, error) {
			m := gobExploitToModel(diff.ExploitsUpdated[i])
			return []interface{}{m.ID, m.Published, m.Updated, m.Author, m.Type, m.Verified, m.SourceURL, m.Description, m.CVEID, m.Tags, m.Forks, m.Watchers, m.Subscribers, m.Stars}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_upd_exploits: %w", err)
		}
	}

	// --- malicious_packages ---
	malPkgCols := []string{"id", "summary", "details", "published", "modified"}
	if err := createLike("_diff_del_malicious_packages", "malicious_packages", "id"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_malicious_packages: %w", err)
	}
	if err := copyIDs(ctx, tx, "_diff_del_malicious_packages", "id", diff.MalPkgsDeleted); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_malicious_packages: %w", err)
	}
	if err := createLike("_diff_ins_malicious_packages", "malicious_packages", strings.Join(malPkgCols, ", ")); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_malicious_packages: %w", err)
	}
	if len(diff.MalPkgsInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_malicious_packages"}, malPkgCols, pgx.CopyFromSlice(len(diff.MalPkgsInserted), func(i int) ([]interface{}, error) {
			m := diff.MalPkgsInserted[i]
			return []interface{}{m.ID, m.Summary, m.Details, m.Published, m.Modified}, nil // nolint:exhaustruct
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_malicious_packages: %w", err)
		}
	}
	if err := createLike("_diff_upd_malicious_packages", "malicious_packages", strings.Join(malPkgCols, ", ")); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_upd_malicious_packages: %w", err)
	}
	if len(diff.MalPkgsUpdated) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_upd_malicious_packages"}, malPkgCols, pgx.CopyFromSlice(len(diff.MalPkgsUpdated), func(i int) ([]interface{}, error) {
			m := diff.MalPkgsUpdated[i]
			return []interface{}{m.ID, m.Summary, m.Details, m.Published, m.Modified}, nil // nolint:exhaustruct
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_upd_malicious_packages: %w", err)
		}
	}

	// --- malicious_affected_components ---
	malCompCols := []string{"id", "malicious_package_id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"}
	if err := createLike("_diff_del_malicious_affected_components", "malicious_affected_components", "id"); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_del_malicious_affected_components: %w", err)
	}
	if err := copyIDs(ctx, tx, "_diff_del_malicious_affected_components", "id", diff.MalCompsDeleted); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_del_malicious_affected_components: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _diff_ins_malicious_affected_components ON COMMIT DROP AS
		SELECT id, malicious_package_id, purl, ecosystem, version::text, semver_introduced::text, semver_fixed::text, version_introduced, version_fixed
		FROM malicious_affected_components WHERE false`); err != nil {
		return fmt.Errorf("computeDiffFromQuickDiff: create _diff_ins_malicious_affected_components: %w", err)
	}
	if len(diff.MalCompsInserted) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_diff_ins_malicious_affected_components"}, malCompCols, pgx.CopyFromSlice(len(diff.MalCompsInserted), func(i int) ([]interface{}, error) {
			mc := diff.MalCompsInserted[i]
			return []interface{}{mc.ID, mc.MaliciousPackageID, mc.PurlWithoutVersion, mc.Ecosystem, mc.Version, mc.SemverIntroduced, mc.SemverFixed, mc.VersionIntroduced, mc.VersionFixed}, nil
		})); err != nil {
			return fmt.Errorf("computeDiffFromQuickDiff: copy _diff_ins_malicious_affected_components: %w", err)
		}
	}

	return nil
}

// applyQuickDiff applies a pre-computed diff directly to the live tables without
// any staging tables or EXCEPT queries. EPSS and CISA KEV are still applied separately.
func applyQuickDiff(ctx context.Context, tx pgx.Tx, diff *QuickDiff) error {
	t := time.Now()

	if err := computeDiffFromQuickDiff(ctx, tx, diff); err != nil {
		return err
	}

	var totalLock time.Duration
	for _, spec := range liveTableSpecs {
		_, _, _, lock, err := applyDiff(ctx, tx, spec)
		if err != nil {
			return err
		}
		totalLock += lock
	}

	slog.Info("quick-diff: applied", "took", time.Since(t), "total_lock_held", totalLock)
	return nil
}

// copyIDs copies a slice of scalar IDs into a single-column temp table.
func copyIDs[T any](ctx context.Context, tx pgx.Tx, tmp, col string, ids []T) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{tmp}, []string{col}, pgx.CopyFromSlice(len(ids), func(i int) ([]interface{}, error) {
		return []interface{}{ids[i]}, nil
	}))
	return err
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// --- row collectors ---

func collectScalars[T any](rows pgx.Rows) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		var v T
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func collectCVERows(rows pgx.Rows) ([]quickDiffCVE, error) {
	defer rows.Close()
	var out []quickDiffCVE
	for rows.Next() {
		var c quickDiffCVE
		if err := rows.Scan(
			&c.ID, &c.ContentHash, &c.CVE, &c.DatePublished, &c.DateLastModified,
			&c.Description, &c.CVSS, &c.References, &c.CISARequiredAction,
			&c.CISAVulnerabilityName, &c.EPSS, &c.Percentile, &c.Vector,
			&c.CISAExploitAdd, &c.CISAActionDue,
		); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func collectRelKeys(rows pgx.Rows) ([]quickDiffRelKey, error) {
	defer rows.Close()
	var out []quickDiffRelKey
	for rows.Next() {
		var r quickDiffRelKey
		if err := rows.Scan(&r.SourceCVE, &r.TargetCVE, &r.RelationshipType); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func collectACRows(rows pgx.Rows) ([]quickDiffAC, error) {
	defer rows.Close()
	var out []quickDiffAC
	for rows.Next() {
		var a quickDiffAC
		if err := rows.Scan(
			&a.ID, &a.Purl, &a.Ecosystem, &a.Version,
			&a.SemverIntroduced, &a.SemverFixed,
			&a.VersionIntroduced, &a.VersionFixed,
		); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func collectPivotRows(rows pgx.Rows) ([]quickDiffPivot, error) {
	defer rows.Close()
	var out []quickDiffPivot
	for rows.Next() {
		var p quickDiffPivot
		if err := rows.Scan(&p.CveID, &p.AffectedComponentID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func collectExploitRows(rows pgx.Rows) ([]GobExploit, error) {
	defer rows.Close()
	var out []GobExploit
	for rows.Next() {
		var e GobExploit
		if err := rows.Scan(
			&e.ID, &e.Published, &e.Updated, &e.Author, &e.Type, &e.Verified,
			&e.SourceURL, &e.Description, &e.CVEID, &e.Tags,
			&e.Forks, &e.Watchers, &e.Subscribers, &e.Stars,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func collectMalPkgRows(rows pgx.Rows) ([]models.MaliciousPackage, error) {
	defer rows.Close()
	var out []models.MaliciousPackage
	for rows.Next() {
		var m models.MaliciousPackage
		if err := rows.Scan(&m.ID, &m.Summary, &m.Details, &m.Published, &m.Modified); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func collectMalCompRows(rows pgx.Rows) ([]GobMaliciousComponent, error) {
	defer rows.Close()
	var out []GobMaliciousComponent
	for rows.Next() {
		var mc GobMaliciousComponent
		if err := rows.Scan(
			&mc.ID, &mc.MaliciousPackageID, &mc.PurlWithoutVersion, &mc.Ecosystem, &mc.Version,
			&mc.SemverIntroduced, &mc.SemverFixed,
			&mc.VersionIntroduced, &mc.VersionFixed,
		); err != nil {
			return nil, err
		}
		out = append(out, mc)
	}
	return out, rows.Err()
}
