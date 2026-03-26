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
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOrgStatistics(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// CVE-A: critical risk (raw_risk_assessment = 9.5, cvss = 9.5)
		cveA := models.CVE{CVE: "CVE-2024-00001", CVSS: 9.5}
		require.NoError(t, f.DB.Create(&cveA).Error)

		// CVE-B: medium risk (raw_risk_assessment = 5.0, cvss = 5.0)
		cveB := models.CVE{CVE: "CVE-2024-00002", CVSS: 5.0}
		require.NoError(t, f.DB.Create(&cveB).Error)

		componentX := models.Component{ID: "pkg:npm/lib-x@1.0.0"}
		componentY := models.Component{ID: "pkg:npm/lib-y@2.0.0"}
		require.NoError(t, f.DB.Create(&componentX).Error)
		require.NoError(t, f.DB.Create(&componentY).Error)

		criticalRisk := 9.5
		mediumRisk := 5.0

		// depVuln1: CVE-A on pkg:X via direct path — counts once in both regular and CVEPurl
		depVuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:             cveA.CVE,
			ComponentPurl:     componentX.ID,
			VulnerabilityPath: []string{componentX.ID},
			RawRiskAssessment: &criticalRisk,
		}
		require.NoError(t, f.DB.Create(&depVuln1).Error)

		// depVuln2: same CVE-A on same pkg:X but via a transitive path — counts in regular
		// counts but must NOT add to CVEPurl (same cve+purl pair)
		depVuln2 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:             cveA.CVE,
			ComponentPurl:     componentX.ID,
			VulnerabilityPath: []string{"pkg:npm/parent@3.0.0", componentX.ID},
			RawRiskAssessment: &criticalRisk,
		}
		require.NoError(t, f.DB.Create(&depVuln2).Error)

		// depVuln3: CVE-B on pkg:Y — unique cve+purl, medium risk
		depVuln3 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:             cveB.CVE,
			ComponentPurl:     componentY.ID,
			VulnerabilityPath: []string{componentY.ID},
			RawRiskAssessment: &mediumRisk,
		}
		require.NoError(t, f.DB.Create(&depVuln3).Error)

		// Call the endpoint
		req := httptest.NewRequest("GET", "/stats/vuln-statistics/", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)
		shared.SetOrg(ctx, org)

		err := f.App.StatisticsController.GetOrgStatistics(ctx)
		require.NoError(t, err)
		assert.Equal(t, 200, rec.Code)

		var resp dtos.OrgOverview
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		dist := resp.VulnDistribution

		// Regular counts include all open rows regardless of path
		assert.Equal(t, 2, dist.Critical, "2 open rows with critical raw_risk_assessment")
		assert.Equal(t, 1, dist.Medium, "1 open row with medium raw_risk_assessment")
		assert.Equal(t, 2, dist.CriticalCVSS, "2 open rows with critical CVSS")
		assert.Equal(t, 1, dist.MediumCVSS, "1 open row with medium CVSS")

		// CVEPurl counts deduplicate on (cve_id, component_purl)
		assert.Equal(t, 1, dist.CVEPurlCritical, "depVuln1 and depVuln2 share the same CVE+purl — should count as 1")
		assert.Equal(t, 1, dist.CVEPurlMedium, "depVuln3 is a unique CVE+purl pair")
		assert.Equal(t, 1, dist.CVEPurlCriticalCVSS, "unique (CVE-A, pkg:X) critical CVSS pair")
		assert.Equal(t, 1, dist.CVEPurlMediumCVSS, "unique (CVE-B, pkg:Y) medium CVSS pair")

		// Totals for sanity
		assert.Equal(t, 0, dist.Low, "no low-risk vulns")
		assert.Equal(t, 0, dist.High, "no high-risk vulns")
		assert.Equal(t, 0, dist.CVEPurlLow)
		assert.Equal(t, 0, dist.CVEPurlHigh)
	})
}
