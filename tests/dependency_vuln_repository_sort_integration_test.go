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
	"fmt"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/require"
)

// Sorting the package-grouped dependency vulns by vulnerability count must use
// the count the UI shows: distinct CVEs per package. A CVE reached through
// several dependency paths is stored once per path, so counting rows put a
// package with one CVE on four paths ahead of a package with three CVEs.
func TestGetByAssetVersionPagedSortsByDistinctCVECount(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	const manyPaths = "pkg:npm/many-paths@1.0.0"
	const manyCVEs = "pkg:npm/many-cves@1.0.0"
	require.NoError(t, db.Create(&models.Component{ID: manyPaths}).Error)
	require.NoError(t, db.Create(&models.Component{ID: manyCVEs}).Error)

	createCVE := func(id string) {
		require.NoError(t, db.Create(&models.CVE{
			CVE:              id,
			CVSS:             5.0,
			DatePublished:    time.Now(),
			DateLastModified: time.Now(),
		}).Error)
	}
	createVuln := func(cveID, purl string, path []string) {
		risk := 1.0
		require.NoError(t, db.Create(&models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:             cveID,
			ComponentPurl:     purl,
			VulnerabilityPath: path,
			RiskAssessment:    &risk,
		}).Error)
	}

	// one CVE, reached through four different paths: four rows, shown as 1
	createCVE("CVE-2026-90000")
	for i := range 4 {
		createVuln("CVE-2026-90000", manyPaths, []string{fmt.Sprintf("pkg:npm/parent-%d@1.0.0", i), manyPaths})
	}
	// three CVEs, one path each: three rows, shown as 3
	for i := 1; i <= 3; i++ {
		cveID := fmt.Sprintf("CVE-2026-9000%d", i)
		createCVE(cveID)
		createVuln(cveID, manyCVEs, []string{manyCVEs})
	}

	repo := repositories.NewDependencyVulnRepository(db)
	for _, tc := range []struct {
		operator string
		want     []string
	}{
		{"desc", []string{manyCVEs, manyPaths}},
		{"asc", []string{manyPaths, manyCVEs}},
	} {
		t.Run(tc.operator, func(t *testing.T) {
			_, order, err := repo.GetByAssetVersionPaged(
				context.Background(), nil, assetVersion.Name, asset.ID,
				shared.PageInfo{Page: 1, PageSize: 10}, "", nil,
				[]shared.SortQuery{{Field: "dependency_vuln_count", Operator: tc.operator}},
			)
			require.NoError(t, err)
			require.Len(t, order, 2)
			require.Equal(t, 0, order[tc.want[0]], "first package")
			require.Equal(t, 1, order[tc.want[1]], "second package")
		})
	}
}
