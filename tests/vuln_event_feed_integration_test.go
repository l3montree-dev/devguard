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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVulnEventFeedPagesDoNotOverlap walks the asset version event feed page by page.
//
// Events are written in batches and routinely share a created_at down to the
// microsecond, so ordering the feed by the timestamp alone leaves postgres free to
// return tied rows in a different order per query - the same event then shows up on
// two pages while another is never returned at all.
func TestVulnEventFeedPagesDoNotOverlap(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		const vulnCount = 12
		sharedTimestamp := time.Now().UTC().Truncate(time.Microsecond)

		for i := range vulnCount {
			cve := models.CVE{CVE: fmt.Sprintf("CVE-2026-FEED-%04d", i), CVSS: 5.0}
			require.NoError(t, f.DB.Create(&cve).Error)

			vuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: assetVersion.Name,
					State:            dtos.VulnStateOpen,
					LastStateChange:  sharedTimestamp,
				},
				CVEID:             cve.CVE,
				ComponentPurl:     fmt.Sprintf("pkg:npm/feed-package-%d@1.0.0", i),
				VulnerabilityPath: []string{fmt.Sprintf("pkg:npm/feed-package-%d@1.0.0", i)},
			}
			require.NoError(t, f.DB.Create(&vuln).Error)

			// every event carries the identical created_at on purpose
			event := models.VulnEvent{
				Type:             dtos.EventTypeDetected,
				UserID:           "system",
				DependencyVulnID: &vuln.ID,
				CreatedAt:        sharedTimestamp,
			}
			require.NoError(t, f.DB.Create(&event).Error)
			require.NoError(t, f.DB.Model(&models.VulnEvent{}).Where("id = ?", event.ID).
				Update("created_at", sharedTimestamp).Error)
		}

		repo := repositories.NewVulnEventRepository(f.DB)

		const pageSize = 4
		seen := make(map[uuid.UUID]int)
		// compared as text: the canonical uuid form is lowercase hex, so lexicographic
		// order matches the byte order postgres sorts by
		var order []string
		for page := 1; page <= vulnCount/pageSize; page++ {
			result, err := repo.ReadEventsByAssetIDAndAssetVersionName(context.Background(), nil,
				asset.ID, assetVersion.Name, shared.PageInfo{Page: page, PageSize: pageSize}, nil)
			require.NoError(t, err)

			assert.Equal(t, int64(vulnCount), result.Total, "total must count the whole feed, not the page")
			assert.Len(t, result.Data, pageSize, "page %d should be full", page)

			for _, event := range result.Data {
				if previous, duplicate := seen[event.ID]; duplicate {
					t.Errorf("event %s returned on page %d and again on page %d", event.ID, previous, page)
				}
				seen[event.ID] = page
				order = append(order, event.ID.String())
			}
		}

		assert.Len(t, seen, vulnCount, "paging through the feed must yield every event exactly once")

		// Every event here shares one created_at, so the feed's order is decided purely
		// by the tiebreaker. Without one the rows come back in whatever order the plan
		// happens to produce, LIMIT/OFFSET slices that shifting order, and pages overlap.
		// Asserting the total order is what actually pins the tiebreaker down - merely
		// checking for duplicates passes by luck at this size.
		assert.IsDecreasing(t, order,
			"with created_at tied, the feed must fall back to a stable descending id order")
	})
}

// TestVulnEventFeedScopesToItsAssetVersion guards the rewritten access path: the feed
// is now reached by joining from the vuln tables rather than filtering vuln_events, so
// the scoping is worth asserting explicitly.
func TestVulnEventFeedScopesToItsAssetVersion(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		_, _, asset, mainVersion := f.CreateOrgProjectAssetAndVersion()
		otherVersion := f.CreateAssetVersion(asset.ID, "other-branch", false)

		cve := models.CVE{CVE: "CVE-2026-FEED-SCOPE", CVSS: 5.0}
		require.NoError(t, f.DB.Create(&cve).Error)

		createEventOn := func(versionName string) uuid.UUID {
			vuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: versionName,
					State:            dtos.VulnStateOpen,
					LastStateChange:  time.Now(),
				},
				CVEID:             cve.CVE,
				ComponentPurl:     "pkg:npm/scope-package@1.0.0",
				VulnerabilityPath: []string{"pkg:npm/scope-package@1.0.0"},
			}
			require.NoError(t, f.DB.Create(&vuln).Error)

			event := models.VulnEvent{
				Type:             dtos.EventTypeDetected,
				UserID:           "system",
				DependencyVulnID: &vuln.ID,
			}
			require.NoError(t, f.DB.Create(&event).Error)
			return event.ID
		}

		mainEvent := createEventOn(mainVersion.Name)
		otherEvent := createEventOn(otherVersion.Name)

		repo := repositories.NewVulnEventRepository(f.DB)
		result, err := repo.ReadEventsByAssetIDAndAssetVersionName(context.Background(), nil,
			asset.ID, mainVersion.Name, shared.PageInfo{Page: 1, PageSize: 10}, nil)
		require.NoError(t, err)

		assert.Equal(t, int64(1), result.Total)
		require.Len(t, result.Data, 1)
		assert.Equal(t, mainEvent, result.Data[0].ID)
		assert.NotEqual(t, otherEvent, result.Data[0].ID,
			"an event belonging to another asset version must not leak into this feed")
		assert.Equal(t, cve.CVE, result.Data[0].CVEID, "the dependency_vulns detail join must still populate cve_id")
	})
}


func TestVulnEventFeedIncludesEveryKindOfVuln(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		cve := models.CVE{CVE: "CVE-2026-FEED-KINDS", CVSS: 5.0}
		require.NoError(t, f.DB.Create(&cve).Error)

		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID: asset.ID, AssetVersionName: assetVersion.Name,
				State: dtos.VulnStateOpen, LastStateChange: time.Now(),
			},
			CVEID:             cve.CVE,
			ComponentPurl:     "pkg:npm/kinds-dependency@1.0.0",
			VulnerabilityPath: []string{"pkg:npm/kinds-dependency@1.0.0"},
		}
		require.NoError(t, f.DB.Create(&dependencyVuln).Error)

		// license_risks.component_purl is a foreign key into components
		require.NoError(t, f.DB.Create(&models.Component{
			ID:            "pkg:npm/kinds-license@1.0.0",
			ComponentType: dtos.ComponentTypeLibrary,
		}).Error)

		licenseRisk := models.LicenseRisk{
			Vulnerability: models.Vulnerability{
				AssetID: asset.ID, AssetVersionName: assetVersion.Name,
				State: dtos.VulnStateOpen, LastStateChange: time.Now(),
			},
			ComponentPurl: "pkg:npm/kinds-license@1.0.0",
		}
		require.NoError(t, f.DB.Create(&licenseRisk).Error)

		firstPartyVuln := models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				AssetID: asset.ID, AssetVersionName: assetVersion.Name,
				State: dtos.VulnStateOpen, LastStateChange: time.Now(),
			},
			URI: "src/kinds.go",
		}
		require.NoError(t, f.DB.Create(&firstPartyVuln).Error)

		require.NoError(t, f.DB.Create(&models.VulnEvent{
			Type: dtos.EventTypeDetected, UserID: "system", DependencyVulnID: &dependencyVuln.ID,
		}).Error)
		require.NoError(t, f.DB.Create(&models.VulnEvent{
			Type: dtos.EventTypeDetected, UserID: "system", LicenseRiskID: &licenseRisk.ID,
		}).Error)
		require.NoError(t, f.DB.Create(&models.VulnEvent{
			Type: dtos.EventTypeDetected, UserID: "system", FirstPartyVulnID: &firstPartyVuln.ID,
		}).Error)

		repo := repositories.NewVulnEventRepository(f.DB)
		result, err := repo.ReadEventsByAssetIDAndAssetVersionName(context.Background(), nil,
			asset.ID, assetVersion.Name, shared.PageInfo{Page: 1, PageSize: 10}, nil)
		require.NoError(t, err)

		assert.Equal(t, int64(3), result.Total, "every kind of vuln event belongs in the feed")

		byType := make(map[dtos.VulnType]models.VulnEventDetail, len(result.Data))
		for _, event := range result.Data {
			byType[event.GetVulnType()] = event
		}

		require.Contains(t, byType, dtos.VulnTypeDependencyVuln)
		assert.Equal(t, cve.CVE, byType[dtos.VulnTypeDependencyVuln].CVEID)
		assert.Equal(t, "pkg:npm/kinds-dependency@1.0.0", byType[dtos.VulnTypeDependencyVuln].ComponentPurl)

		require.Contains(t, byType, dtos.VulnTypeLicenseRisk, "license risk events were missing from the feed entirely")
		assert.Equal(t, "pkg:npm/kinds-license@1.0.0", byType[dtos.VulnTypeLicenseRisk].ComponentPurl,
			"a license risk names its component in the same DTO field a dependency vuln does")

		require.Contains(t, byType, dtos.VulnTypeFirstPartyVuln)
		assert.Equal(t, "src/kinds.go", byType[dtos.VulnTypeFirstPartyVuln].URI)
	})
}
