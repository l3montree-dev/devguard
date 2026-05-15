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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
)

const (
	testVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

func makeCVE(id int64, cveStr, desc string, cvss float32, vector string) models.CVE {
	cve := models.CVE{
		CVE:         cveStr,
		Description: desc,
		CVSS:        cvss,
		Vector:      vector,
	}
	cve.ID = id
	cve.ContentHash = cve.CalculateContentHash()
	return cve
}

// seedCVEState inserts the given CVEs (plus optional EPSS/KEV) as the current
// live-table state via staging→sync, so the DB reflects exactly this set.
func seedCVEState(ctx context.Context, t *testing.T, pool *pgxpool.Pool, cves []models.CVE, rels []models.CVERelationship, epss map[string]dtos.EPSS, kev []vulndb.CISAKEVEntry) {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	assert.NoError(t, err)
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	assert.NoError(t, err)
	defer tx.Rollback(ctx) //nolint:errcheck

	assert.NoError(t, vulndb.CreateStagingTables(ctx, tx))
	assert.NoError(t, vulndb.InsertCVEsBulk(ctx, tx, cves, "cves_stage"))
	if len(rels) > 0 {
		assert.NoError(t, vulndb.InsertCVERelationshipsBulk(ctx, tx, rels, "cve_relationships_stage"))
	}
	assert.NoError(t, vulndb.SyncAllTables(ctx, tx))
	assert.NoError(t, vulndb.InsertEPSSBulk(ctx, tx, epss))
	assert.NoError(t, vulndb.InsertCISAKEVBulk(ctx, tx, kev))

	assert.NoError(t, tx.Commit(ctx))
}

// simulateExport truncates, loads new CVEs+rels into the live tables (mirroring exportRC),
// applies EPSS/KEV, computes and returns the quickdiff + ground-truth integrity.
func simulateExport(
	ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	prevVersion time.Time,
	newCVEs []models.CVE, newRels []models.CVERelationship,
	newEPSS map[string]dtos.EPSS, newKEV []vulndb.CISAKEVEntry,
) (*vulndb.QuickDiff, vulndb.IntegrityInformation) {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	assert.NoError(t, err)
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	assert.NoError(t, err)
	defer tx.Rollback(ctx) //nolint:errcheck

	assert.NoError(t, vulndb.SnapshotPrevState(ctx, tx))
	assert.NoError(t, vulndb.TruncateCVERelatedTables(ctx, tx))
	assert.NoError(t, vulndb.CreateStagingTables(ctx, tx))
	assert.NoError(t, vulndb.InsertCVEsBulk(ctx, tx, newCVEs, "cves_stage"))
	if len(newRels) > 0 {
		assert.NoError(t, vulndb.InsertCVERelationshipsBulk(ctx, tx, newRels, "cve_relationships_stage"))
	}
	assert.NoError(t, vulndb.FlushOSVStagingTables(ctx, tx))
	assert.NoError(t, vulndb.InsertEPSSBulk(ctx, tx, newEPSS))
	assert.NoError(t, vulndb.InsertCISAKEVBulk(ctx, tx, newKEV))

	diff, err := vulndb.ComputeQuickDiff(ctx, tx, prevVersion)
	assert.NoError(t, err)

	groundTruthSlice, err := vulndb.CalculateTotalIntegrityInformation(ctx, tx)
	assert.NoError(t, err)
	groundTruth := vulndb.IntegrityInformation{TableIntegrity: groundTruthSlice, ImportTimestamp: time.Now()}

	assert.NoError(t, tx.Commit(ctx))
	return diff, groundTruth
}

// applyQuickDiffAndVerify applies a decoded quickdiff + EPSS + KEV to the current
// DB state (which must already be the prev-version state) and checks the integrity
// checksum against the ground truth.
func applyQuickDiffAndVerify(
	ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	decoded *vulndb.QuickDiff,
	newEPSS map[string]dtos.EPSS, newKEV []vulndb.CISAKEVEntry,
	groundTruth vulndb.IntegrityInformation,
) {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	assert.NoError(t, err)
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	assert.NoError(t, err)
	defer tx.Rollback(ctx) //nolint:errcheck

	assert.NoError(t, vulndb.ApplyQuickDiff(ctx, tx, decoded))
	assert.NoError(t, vulndb.InsertEPSSBulk(ctx, tx, newEPSS))
	assert.NoError(t, vulndb.InsertCISAKEVBulk(ctx, tx, newKEV))

	localIntegrity, err := vulndb.CalculateTotalIntegrityInformation(ctx, tx)
	assert.NoError(t, err)

	failingTables, ok := vulndb.ValidateIntegrityInformation("", groundTruth, localIntegrity)
	assert.True(t, ok, "integrity check failed for tables: %v", failingTables)

	// On failure: print per-row detail to show which CVEs differ.
	if !ok {
		rows, qErr := tx.Query(ctx, `SELECT id, cve, description, cvss, vector, epss, percentile, cisa_required_action, cisa_vulnerability_name FROM cves ORDER BY id LIMIT 50`)
		if qErr == nil {
			defer rows.Close()
			t.Log("=== CVE rows in importer DB after quickdiff ===")
			for rows.Next() {
				var id int64
				var cveStr, desc, vector string
				var cvss float32
				var epss, pct *float64
				var cisaAction, cisaName *string
				_ = rows.Scan(&id, &cveStr, &desc, &cvss, &vector, &epss, &pct, &cisaAction, &cisaName)
				t.Logf("  id=%d cve=%s cvss=%.2f epss=%v cisa_action=%v", id, cveStr, cvss, epss, cisaAction)
			}
		}
	}
}

func roundtripDiff(t *testing.T, diff *vulndb.QuickDiff) *vulndb.QuickDiff {
	t.Helper()
	var buf bytes.Buffer
	assert.NoError(t, gob.NewEncoder(&buf).Encode(diff))
	var decoded vulndb.QuickDiff
	assert.NoError(t, gob.NewDecoder(&buf).Decode(&decoded))
	return &decoded
}

// --- Scenarios ---

// TestQuickDiff_BalancedAddDelete is the exact pattern seen in production:
// the same number of CVEs are added and deleted so row counts remain equal,
// but checksums will differ if the quickdiff misses any change.
func TestQuickDiffBalancedAddDelete(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	prevCVEs := []models.CVE{
		makeCVE(1001, "CVE-2021-1001", "desc A", 7.8, testVector),
		makeCVE(1002, "CVE-2021-1002", "desc B", 5.0, testVector),
		makeCVE(1003, "CVE-2021-1003", "desc C to be deleted", 3.0, testVector),
		makeCVE(1004, "CVE-2021-1004", "desc D to be deleted", 4.0, testVector),
	}
	prevEPSS := map[string]dtos.EPSS{
		"CVE-2021-1001": {EPSS: 0.10, Percentile: 0.50},
		"CVE-2021-1002": {EPSS: 0.20, Percentile: 0.60},
		"CVE-2021-1003": {EPSS: 0.30, Percentile: 0.70},
		"CVE-2021-1004": {EPSS: 0.40, Percentile: 0.80},
	}

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	prevVersion := time.Now()

	// Delete 1003 and 1004, add 1005 and 1006 — count stays at 4.
	newCVEs := []models.CVE{
		makeCVE(1001, "CVE-2021-1001", "desc A", 7.8, testVector),
		makeCVE(1002, "CVE-2021-1002", "desc B", 5.0, testVector),
		makeCVE(1005, "CVE-2021-1005", "brand new E", 9.0, testVector),
		makeCVE(1006, "CVE-2021-1006", "brand new F", 8.5, testVector),
	}
	newEPSS := map[string]dtos.EPSS{
		"CVE-2021-1001": {EPSS: 0.10, Percentile: 0.50},
		"CVE-2021-1002": {EPSS: 0.20, Percentile: 0.60},
		"CVE-2021-1005": {EPSS: 0.85, Percentile: 0.90},
		"CVE-2021-1006": {EPSS: 0.75, Percentile: 0.85},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, newCVEs, nil, newEPSS, nil)
	assert.Len(t, diff.CVEsDeleted, 2, "expected 2 deleted CVEs")
	assert.Len(t, diff.CVEsInserted, 2, "expected 2 inserted CVEs")

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), newEPSS, nil, groundTruth)
}

// TestQuickDiff_ContentAndEPSSChangeSimultaneously tests a CVE where description
// changes (content_hash changes → in CVEsUpdated) AND EPSS changes at the same time.
// The CVEsUpdated row carries the new EPSS value from the export, but InsertEPSSBulk
// resets all EPSS and re-applies — those two operations must produce the same result.
func TestQuickDiffContentAndEPSSChangeSimultaneously(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	prevCVEs := []models.CVE{
		makeCVE(2001, "CVE-2022-2001", "old description", 7.0, testVector),
	}
	prevEPSS := map[string]dtos.EPSS{
		"CVE-2022-2001": {EPSS: 0.10, Percentile: 0.50},
	}

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	prevVersion := time.Now()

	newCVEs := []models.CVE{
		makeCVE(2001, "CVE-2022-2001", "updated description", 7.0, testVector),
	}
	newEPSS := map[string]dtos.EPSS{
		"CVE-2022-2001": {EPSS: 0.99, Percentile: 0.999},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, newCVEs, nil, newEPSS, nil)
	assert.Len(t, diff.CVEsUpdated, 1, "expected 1 updated CVE")

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), newEPSS, nil, groundTruth)
}

// TestQuickDiff_EPSSOnlyChange verifies a CVE where content_hash is unchanged
// but EPSS changes. The CVE must NOT appear in CVEsUpdated; InsertEPSSBulk covers it.
func TestQuickDiffEPSSOnlyChange(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	prevCVEs := []models.CVE{
		makeCVE(3001, "CVE-2023-3001", "stable description", 6.0, testVector),
	}
	prevEPSS := map[string]dtos.EPSS{
		"CVE-2023-3001": {EPSS: 0.10, Percentile: 0.40},
	}

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	prevVersion := time.Now()

	newEPSS := map[string]dtos.EPSS{
		"CVE-2023-3001": {EPSS: 0.99, Percentile: 0.999},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, prevCVEs, nil, newEPSS, nil)
	assert.Empty(t, diff.CVEsUpdated, "expected no content updates when only EPSS changed")

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), newEPSS, nil, groundTruth)
}

// TestQuickDiff_CISAKEVAdded tests a CVE that was not in the KEV list and then gets added.
// InsertCISAKEVBulk must reset all CISA fields and re-apply — the CVE should end up
// with the new CISA values, not its old NULL values.
func TestQuickDiffCISAKEVAdded(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	prevCVEs := []models.CVE{
		makeCVE(4001, "CVE-2024-4001", "exploitable vuln", 9.8, testVector),
	}
	seedCVEState(ctx, t, pool, prevCVEs, nil, nil, nil)
	prevVersion := time.Now()

	newKEV := []vulndb.CISAKEVEntry{
		{CVE: "CVE-2024-4001", RequiredAction: "patch immediately", VulnerabilityName: "Super Bug"},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, prevCVEs, nil, nil, newKEV)
	assert.Empty(t, diff.CVEsUpdated, "CISA change must not appear in CVEsUpdated (not part of content_hash)")

	seedCVEState(ctx, t, pool, prevCVEs, nil, nil, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), nil, newKEV, groundTruth)
}

// TestQuickDiff_CISAKEVRemoved tests a CVE that was in the KEV list and then gets removed.
// After InsertCISAKEVBulk reset, the CISA fields must be NULL.
func TestQuickDiffCISAKEVRemoved(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	prevCVEs := []models.CVE{
		makeCVE(5001, "CVE-2024-5001", "was in KEV", 8.0, testVector),
	}
	prevKEV := []vulndb.CISAKEVEntry{
		{CVE: "CVE-2024-5001", RequiredAction: "apply workaround", VulnerabilityName: "Old Bug"},
	}

	seedCVEState(ctx, t, pool, prevCVEs, nil, nil, prevKEV)
	prevVersion := time.Now()

	// New export: KEV entry removed — pass empty KEV.
	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, prevCVEs, nil, nil, nil)
	assert.Empty(t, diff.CVEsUpdated)

	seedCVEState(ctx, t, pool, prevCVEs, nil, nil, prevKEV)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), nil, nil, groundTruth)
}

// TestQuickDiff_EPSSPropagationViaRelationship verifies that EPSS propagates to alias
// CVEs via cve_relationships. Both paths (export and quickdiff import) must produce the
// same EPSS on the alias CVE.
func TestQuickDiffEPSSPropagationViaRelationship(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	// CVE-A aliases CVE-B (source=A, target=B). CVE-B has EPSS.
	// CVE-A should inherit CVE-B's EPSS via InsertEPSSBulk propagation.
	cveBID := int64(6002)
	cveAID := int64(6001)
	prevCVEs := []models.CVE{
		makeCVE(cveAID, "CVE-2025-6001", "alias CVE", 5.0, testVector),
		makeCVE(cveBID, "CVE-2025-6002", "canonical CVE with EPSS", 7.0, testVector),
	}
	prevRels := []models.CVERelationship{
		{SourceCVE: "CVE-2025-6001", TargetCVE: "CVE-2025-6002", RelationshipType: "alias"},
	}
	prevEPSS := map[string]dtos.EPSS{
		"CVE-2025-6002": {EPSS: 0.80, Percentile: 0.90},
	}

	seedCVEState(ctx, t, pool, prevCVEs, prevRels, prevEPSS, nil)
	prevVersion := time.Now()

	// New state: CVE-B EPSS changes. CVE-A should inherit the new value.
	newEPSS := map[string]dtos.EPSS{
		"CVE-2025-6002": {EPSS: 0.95, Percentile: 0.99},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, prevCVEs, prevRels, newEPSS, nil)
	assert.Empty(t, diff.CVEsUpdated, "EPSS-only change must not appear in CVEsUpdated")

	seedCVEState(ctx, t, pool, prevCVEs, prevRels, prevEPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), newEPSS, nil, groundTruth)
}

// TestQuickDiff_NewRelationshipCausesEPSSPropagation tests the case where a NEW
// cve_relationship is added and EPSS must propagate through it.
func TestQuickDiffNewRelationshipCausesEPSSPropagation(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	// Prev: two independent CVEs, only CVE-B has EPSS, no relationship.
	prevCVEs := []models.CVE{
		makeCVE(7001, "CVE-2025-7001", "alias CVE (no EPSS yet)", 5.0, testVector),
		makeCVE(7002, "CVE-2025-7002", "canonical CVE", 7.0, testVector),
	}
	prevEPSS := map[string]dtos.EPSS{
		"CVE-2025-7002": {EPSS: 0.80, Percentile: 0.90},
	}

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	prevVersion := time.Now()

	// New: relationship added — CVE-7001 should now inherit CVE-7002's EPSS.
	newRels := []models.CVERelationship{
		{SourceCVE: "CVE-2025-7001", TargetCVE: "CVE-2025-7002", RelationshipType: "alias"},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, prevCVEs, newRels, prevEPSS, nil)
	assert.Len(t, diff.RelationshipsInserted, 1)

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), prevEPSS, nil, groundTruth)
}

// TestQuickDiff_CISAViaRelationship tests CISA KEV propagation to an alias CVE
// when the relationship already existed before this export round.
func TestQuickDiffCISAViaRelationship(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	prevCVEs := []models.CVE{
		makeCVE(8001, "CVE-2025-8001", "alias CVE", 5.0, testVector),
		makeCVE(8002, "CVE-2025-8002", "canonical CVE", 9.0, testVector),
	}
	prevRels := []models.CVERelationship{
		{SourceCVE: "CVE-2025-8001", TargetCVE: "CVE-2025-8002", RelationshipType: "alias"},
	}

	seedCVEState(ctx, t, pool, prevCVEs, prevRels, nil, nil)
	prevVersion := time.Now()

	// New: CVE-B added to CISA KEV — CVE-A (alias) must also get the CISA data.
	newKEV := []vulndb.CISAKEVEntry{
		{CVE: "CVE-2025-8002", RequiredAction: "patch now", VulnerabilityName: "Critical Bug"},
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, prevCVEs, prevRels, nil, newKEV)

	seedCVEState(ctx, t, pool, prevCVEs, prevRels, nil, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), nil, newKEV, groundTruth)
}

// TestQuickDiff_LargeBatchManyChanges exercises a large number of simultaneous
// inserts, deletes, updates, and EPSS changes to surface any batch-size edge cases.
func TestQuickDiffLargeBatchManyChanges(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	const n = 200
	prevCVEs := make([]models.CVE, n)
	prevEPSS := make(map[string]dtos.EPSS, n)
	for i := range n {
		id := int64(9000 + i)
		cveStr := fmt.Sprintf("CVE-2020-%04d", i)
		prevCVEs[i] = makeCVE(id, cveStr, fmt.Sprintf("description %d", i), float32(i%10)+0.5, testVector)
		prevEPSS[cveStr] = dtos.EPSS{EPSS: float64(i) / float64(n), Percentile: float64(i) / float64(n)}
	}

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	prevVersion := time.Now()

	// Keep first 150, delete last 50, add 50 new ones, update 30 of the kept ones.
	newCVEs := make([]models.CVE, 0, n)
	newEPSS := make(map[string]dtos.EPSS, n)
	for i := range 150 {
		cve := prevCVEs[i]
		if i < 30 {
			cve = makeCVE(cve.ID, cve.CVE, fmt.Sprintf("updated description %d", i), cve.CVSS, testVector)
		}
		newCVEs = append(newCVEs, cve)
		cveStr := fmt.Sprintf("CVE-2020-%04d", i)
		newEPSS[cveStr] = dtos.EPSS{EPSS: float64(i+1) / float64(n), Percentile: float64(i+1) / float64(n)}
	}
	for i := range 50 {
		id := int64(9500 + i)
		cveStr := fmt.Sprintf("CVE-2021-%04d", i)
		newCVEs = append(newCVEs, makeCVE(id, cveStr, fmt.Sprintf("new CVE %d", i), 5.0, testVector))
		newEPSS[cveStr] = dtos.EPSS{EPSS: 0.5, Percentile: 0.5}
	}

	diff, groundTruth := simulateExport(ctx, t, pool, prevVersion, newCVEs, nil, newEPSS, nil)

	seedCVEState(ctx, t, pool, prevCVEs, nil, prevEPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff), newEPSS, nil, groundTruth)
}

// TestQuickDiff_SequentialImports simulates two consecutive quickdiff cycles.
// The second cycle uses the importer's DB state after the first quickdiff as its
// baseline — any accumulated drift will surface here.
func TestQuickDiffSequentialImports(t *testing.T) {
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	v1CVEs := []models.CVE{
		makeCVE(10001, "CVE-2026-0001", "v1 desc A", 7.0, testVector),
		makeCVE(10002, "CVE-2026-0002", "v1 desc B", 5.0, testVector),
	}
	v1EPSS := map[string]dtos.EPSS{
		"CVE-2026-0001": {EPSS: 0.1, Percentile: 0.4},
		"CVE-2026-0002": {EPSS: 0.2, Percentile: 0.5},
	}

	seedCVEState(ctx, t, pool, v1CVEs, nil, v1EPSS, nil)
	v1Time := time.Now()

	// --- Round 1: update 0001, add 0003 ---
	v2CVEs := []models.CVE{
		makeCVE(10001, "CVE-2026-0001", "v2 desc A updated", 7.0, testVector),
		makeCVE(10002, "CVE-2026-0002", "v1 desc B", 5.0, testVector),
		makeCVE(10003, "CVE-2026-0003", "v2 new C", 9.0, testVector),
	}
	v2EPSS := map[string]dtos.EPSS{
		"CVE-2026-0001": {EPSS: 0.5, Percentile: 0.7},
		"CVE-2026-0002": {EPSS: 0.2, Percentile: 0.5},
		"CVE-2026-0003": {EPSS: 0.9, Percentile: 0.95},
	}

	diff1, gt1 := simulateExport(ctx, t, pool, v1Time, v2CVEs, nil, v2EPSS, nil)
	seedCVEState(ctx, t, pool, v1CVEs, nil, v1EPSS, nil)
	// Apply round-1 quickdiff and commit so the DB is the importer's v2 state.
	applyAndCommit := func(decoded *vulndb.QuickDiff, epss map[string]dtos.EPSS, kev []vulndb.CISAKEVEntry) {
		t.Helper()
		conn, err := pool.Acquire(ctx)
		assert.NoError(t, err)
		defer conn.Release()
		tx, err := conn.Begin(ctx)
		assert.NoError(t, err)
		assert.NoError(t, vulndb.ApplyQuickDiff(ctx, tx, decoded))
		assert.NoError(t, vulndb.InsertEPSSBulk(ctx, tx, epss))
		assert.NoError(t, vulndb.InsertCISAKEVBulk(ctx, tx, kev))
		assert.NoError(t, tx.Commit(ctx))
	}
	applyAndCommit(roundtripDiff(t, diff1), v2EPSS, nil)

	// Verify round 1 integrity.
	verifyIntegrity := func(tx pgx.Tx, groundTruth vulndb.IntegrityInformation, label string) {
		t.Helper()
		local, err := vulndb.CalculateTotalIntegrityInformation(ctx, tx)
		assert.NoError(t, err)
		failingTables, ok := vulndb.ValidateIntegrityInformation("", groundTruth, local)
		assert.True(t, ok, "%s: integrity check failed for tables: %v", label, failingTables)
	}

	conn, err := pool.Acquire(ctx)
	assert.NoError(t, err)
	tx, err := conn.Begin(ctx)
	assert.NoError(t, err)
	verifyIntegrity(tx, gt1, "round 1")
	tx.Rollback(ctx) //nolint:errcheck
	conn.Release()

	// --- Round 2: update 0002, delete 0001, add 0004 ---
	v2Time := time.Now()
	v3CVEs := []models.CVE{
		makeCVE(10002, "CVE-2026-0002", "v3 desc B updated", 6.0, testVector),
		makeCVE(10003, "CVE-2026-0003", "v2 new C", 9.0, testVector),
		makeCVE(10004, "CVE-2026-0004", "v3 new D", 4.0, testVector),
	}
	v3EPSS := map[string]dtos.EPSS{
		"CVE-2026-0002": {EPSS: 0.6, Percentile: 0.8},
		"CVE-2026-0003": {EPSS: 0.9, Percentile: 0.95},
		"CVE-2026-0004": {EPSS: 0.3, Percentile: 0.4},
	}

	// simulateExport commits v3 into the DB; restore the importer side to v2 first.
	diff2, gt2 := simulateExport(ctx, t, pool, v2Time, v3CVEs, nil, v3EPSS, nil)
	seedCVEState(ctx, t, pool, v2CVEs, nil, v2EPSS, nil)
	applyQuickDiffAndVerify(ctx, t, pool, roundtripDiff(t, diff2), v3EPSS, nil, gt2)
}
