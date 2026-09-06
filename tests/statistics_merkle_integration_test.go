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
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests prove the statistics queries ported to the content-addressed
// (Merkle) SBOM storage produce correct results, since the recursive CTEs
// they rely on cannot be checked in a unit test.

func TestStatisticsQueriesAgainstMerkleSBOMs(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	org, project, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	sbomRepo := repositories.NewSBOMRepository(db)
	statsRepo := repositories.NewStatisticsRepository(db)
	ctx := context.Background()

	// -- seed data ---------------------------------------------------------

	// two artifacts of the same asset both report the same direct component
	// "pkg:npm/shared@1.0.0" - it must be counted once per asset, not once
	// per artifact/SBOM.
	sharedTree := tree(map[string][]string{
		"root-ref": {"pkg:npm/shared@1.0.0"},
	}, "artifact-one")
	require.NoError(t, sbomRepo.SaveTree(ctx, nil, sbomFor(assetVersion, "artifact-one", "sbom:lock.json"), sharedTree))

	sharedTree2 := tree(map[string][]string{
		"root-ref": {"pkg:npm/shared@1.0.0"},
	}, "artifact-two")
	require.NoError(t, sbomRepo.SaveTree(ctx, nil, sbomFor(assetVersion, "artifact-two", "sbom:lock.json"), sharedTree2))

	// a transitive-only component, several levels deep, plus a golang
	// ecosystem component to prove ecosystem extraction works across
	// ecosystems.
	transitiveTree := tree(map[string][]string{
		"root-ref":                 {"pkg:npm/direct@1.0.0"},
		"pkg:npm/direct@1.0.0":     {"pkg:npm/transitive@1.0.0"},
		"pkg:npm/transitive@1.0.0": {"pkg:golang/deep-transitive@1.0.0"},
	}, "artifact-three")
	require.NoError(t, sbomRepo.SaveTree(ctx, nil, sbomFor(assetVersion, "artifact-three", "sbom:lock.json"), transitiveTree))

	// a malicious package, matched against a component in the tree above
	maliciousPkg := models.MaliciousPackage{
		ID:        "MAL-0001",
		Summary:   "evil package",
		Published: time.Now(),
		Modified:  time.Now(),
	}
	require.NoError(t, db.Create(&maliciousPkg).Error)
	maliciousComponent := models.MaliciousAffectedComponent{
		MaliciousPackageID: maliciousPkg.ID,
		PurlWithoutVersion: "pkg:npm/transitive@1.0.0",
		Ecosystem:          "npm",
	}
	require.NoError(t, db.Create(&maliciousComponent).Error)

	// a components row so the average-age query has something to average
	published := time.Now().Add(-48 * time.Hour)
	require.NoError(t, db.Create(&models.Component{
		ID:        "pkg:npm/shared@1.0.0",
		Published: &published,
	}).Error)

	t.Run("GetMostUsedComponentsInOrg counts a component once per asset even when several SBOMs report it", func(t *testing.T) {
		components, err := statsRepo.GetMostUsedComponentsInOrg(ctx, nil, org.ID, 100)
		require.NoError(t, err)

		var found *int
		for _, c := range components {
			if c.PackageURL == "pkg:npm/shared@1.0.0" {
				v := c.TotalAmountInOrg
				found = &v
			}
		}
		require.NotNil(t, found, "shared component must appear")
		assert.Equal(t, 1, *found, "one asset reporting a component via two artifacts must count once")
	})

	t.Run("GetMostUsedComponentsInOrg surfaces transitive components", func(t *testing.T) {
		components, err := statsRepo.GetMostUsedComponentsInOrg(ctx, nil, org.ID, 100)
		require.NoError(t, err)

		purls := make([]string, 0, len(components))
		for _, c := range components {
			purls = append(purls, c.PackageURL)
		}
		assert.Contains(t, purls, "pkg:npm/transitive@1.0.0")
		assert.Contains(t, purls, "pkg:golang/deep-transitive@1.0.0", "a component nested several levels deep must still be reachable")
	})

	t.Run("GetEcosystemDistributionInOrg extracts the ecosystem from the purl", func(t *testing.T) {
		distribution, err := statsRepo.GetEcosystemDistributionInOrg(ctx, nil, org.ID)
		require.NoError(t, err)

		ecosystems := make(map[string]int)
		for _, e := range distribution {
			ecosystems[e.Ecosystem] = e.TotalCount
		}
		assert.Contains(t, ecosystems, "npm")
		assert.Contains(t, ecosystems, "golang")
		assert.Positive(t, ecosystems["npm"])
		assert.Positive(t, ecosystems["golang"])
	})

	t.Run("FindMaliciousPackagesInOrg matches a malicious transitive component", func(t *testing.T) {
		packages, err := statsRepo.FindMaliciousPackagesInOrg(ctx, nil, org.ID)
		require.NoError(t, err)

		require.Len(t, packages, 1)
		assert.Equal(t, "MAL-0001", packages[0].MaliciousPackageID)
		assert.Equal(t, "pkg:npm/transitive@1.0.0", packages[0].Component)
		assert.Equal(t, project.Name, packages[0].ProjectName)
		assert.Equal(t, asset.Name, packages[0].AssetName)
		assert.Equal(t, assetVersion.Name, packages[0].AssetVersionName)
	})

	t.Run("FindMaliciousPackagesAcrossInstance matches the same component instance-wide", func(t *testing.T) {
		packages, err := statsRepo.FindMaliciousPackagesAcrossInstance(ctx, nil)
		require.NoError(t, err)

		require.Len(t, packages, 1)
		assert.Equal(t, "MAL-0001", packages[0].MaliciousPackageID)
		assert.Equal(t, "pkg:npm/transitive@1.0.0", packages[0].Component)
		assert.Equal(t, org.Slug, packages[0].OrgSlug)
		assert.Equal(t, project.Slug, packages[0].ProjectSlug)
		assert.Equal(t, asset.Slug, packages[0].AssetSlug)
		assert.Equal(t, asset.Name, packages[0].AssetName)
		assert.Equal(t, assetVersion.Name, packages[0].AssetVersionName)
	})

	t.Run("GetTopComponentsAcrossInstance counts a component once per asset instance-wide", func(t *testing.T) {
		components, err := statsRepo.GetTopComponentsAcrossInstance(ctx, nil, 100)
		require.NoError(t, err)

		var found *dtoComponentOccurrence
		for _, c := range components {
			if c.PackageURL == "pkg:npm/shared@1.0.0" {
				found = &dtoComponentOccurrence{total: c.TotalAmount, relative: c.RelativeAmount}
			}
		}
		require.NotNil(t, found)
		assert.Equal(t, 1, found.total)
		assert.Positive(t, found.relative)
	})

	t.Run("GetAverageAgeOfDependenciesAcrossOrg averages the published date of reachable components", func(t *testing.T) {
		age, err := statsRepo.GetAverageAgeOfDependenciesAcrossOrg(ctx, nil, org.ID)
		require.NoError(t, err)
		assert.Greater(t, age, 40*time.Hour)
		assert.Less(t, age, 56*time.Hour)
	})
}

type dtoComponentOccurrence struct {
	total    int
	relative float64
}
