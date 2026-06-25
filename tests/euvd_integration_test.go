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

package tests

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
)

// queryEUVDRelationships returns the euvd-derived rows (target_cve is an EUVD id) as
// "target|source|type" keys.
func queryEUVDRelationships(ctx context.Context, t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	assert.NoError(t, err)
	defer conn.Release()

	rows, err := conn.Query(ctx, `SELECT target_cve, source_cve, relationship_type FROM cve_relationships WHERE target_cve LIKE 'EUVD-%'`)
	assert.NoError(t, err)
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var target, source, relType string
		assert.NoError(t, rows.Scan(&target, &source, &relType))
		keys = append(keys, target+"|"+source+"|"+relType)
	}
	assert.NoError(t, rows.Err())
	return keys
}

// TestResolveEUVDRelationships verifies the resolution: an EUVD id becomes the target_cve and every
// cve related to its original cve becomes a source (keeping that relation's type); an EUVD id whose
// cve has no relationship is kept only when the cve exists in the cves table.
func TestResolveEUVDRelationships(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	cves := []models.CVE{
		makeCVE(9301, "CVE-2024-0001", "original cve with an alias", 5.0, testVector),
		makeCVE(9302, "CVE-2024-0002", "the alias of 0001", 6.0, testVector),
		makeCVE(9303, "CVE-2024-0003", "standalone cve present in cves", 7.0, testVector),
	}
	// CVE-2024-0002 is an alias of CVE-2024-0001 (source -> target).
	rels := []models.CVERelationship{
		{SourceCVE: "CVE-2024-0002", TargetCVE: "CVE-2024-0001", RelationshipType: "alias"},
	}
	seedCVEState(ctx, t, pool, cves, rels, nil, nil)

	// raw EUVD csv mapping: source = EUVD id, target = original cve.
	rawEUVD := []models.CVERelationship{
		{SourceCVE: "EUVD-2024-1", TargetCVE: "CVE-2024-0001", RelationshipType: "euvd"}, // has an alias -> resolved
		{SourceCVE: "EUVD-2024-3", TargetCVE: "CVE-2024-0003", RelationshipType: "euvd"}, // no relationship, in cves -> fallback kept
		{SourceCVE: "EUVD-2024-9", TargetCVE: "CVE-2024-9999", RelationshipType: "euvd"}, // no relationship, not in cves -> dropped
	}

	conn, err := pool.Acquire(ctx)
	assert.NoError(t, err)
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	assert.NoError(t, err)
	defer tx.Rollback(ctx) //nolint:errcheck

	resolved, err := vulndb.NewEUVDService(nil, nil, pool).ResolveAndInsertEUVDRelationships(ctx, tx, rawEUVD)
	assert.NoError(t, err)
	assert.NoError(t, tx.Commit(ctx))

	// the returned (gob-bound) rows must be exactly the resolved alias and the fallback.
	returned := make([]string, 0, len(resolved))
	for _, r := range resolved {
		returned = append(returned, r.TargetCVE+"|"+r.SourceCVE+"|"+r.RelationshipType)
	}
	assert.ElementsMatch(t, []string{
		"EUVD-2024-1|CVE-2024-0002|alias", // resolved: alias source linked to the EUVD id, type kept
		"EUVD-2024-3|CVE-2024-0003|euvd",  // fallback: direct link kept because the cve exists in cves
	}, returned)

	// the live table must hold the same euvd-derived rows and no raw source=EUVD rows.
	assert.ElementsMatch(t, []string{
		"EUVD-2024-1|CVE-2024-0002|alias",
		"EUVD-2024-3|CVE-2024-0003|euvd",
	}, queryEUVDRelationships(ctx, t, pool))
}
