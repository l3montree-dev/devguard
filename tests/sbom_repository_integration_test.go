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

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The merkle queries are recursive CTEs whose termination and deduplication
// behaviour cannot be checked in a unit test, so they run against a real
// Postgres here.

func tree(children map[string][]string, artifactID string) *normalize.MerkleTree {
	return normalize.BuildMerkleTree(
		normalize.Adjacency{Children: children, ComponentIDs: map[string]string{}},
		"root-ref",
		artifactID,
	)
}

func countEdges(t *testing.T, db shared.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.SBOMMerkleEdge{}).Count(&n).Error)
	return n
}

func sbomFor(assetVersion models.AssetVersion, artifactName, origin string) models.SBOM {
	return models.SBOM{
		AssetID:          assetVersion.AssetID,
		AssetVersionName: assetVersion.Name,
		ArtifactName:     artifactName,
		Origin:           origin,
	}
}

func TestSBOMRepositoryStoresAndReloadsTrees(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, _, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewSBOMRepository(db)
	ctx := context.Background()

	t.Run("a stored tree reloads identically", func(t *testing.T) {
		original := tree(map[string][]string{
			"root-ref":        {"pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/leaf@1.0.0"},
		}, "round-trip-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "round-trip-app", "sbom:lock.json"), original))

		loaded, err := repo.LoadTree(ctx, nil, original.Root)
		require.NoError(t, err)

		assert.Equal(t, original.Root, loaded.Root)
		assert.Equal(t, original.Len(), loaded.Len())
		assert.Equal(t, original.ComponentIDs(), loaded.ComponentIDs())
		assert.Equal(t, original.DirectDependencies(), loaded.DirectDependencies())
	})

	t.Run("a leaf reloads with its component id, from its NULL row", func(t *testing.T) {
		original := tree(map[string][]string{
			"root-ref": {"pkg:npm/only-leaf@1.0.0"},
		}, "leaf-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "leaf-app", "sbom:lock.json"), original))

		loaded, err := repo.LoadTree(ctx, nil, original.Root)
		require.NoError(t, err)
		assert.Equal(t, []string{"pkg:npm/only-leaf@1.0.0"}, loaded.ComponentIDs())
	})

	t.Run("paths survive the round trip, because vuln hashes depend on them", func(t *testing.T) {
		original := tree(map[string][]string{
			"root-ref":        {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/target@1.0.0"},
		}, "path-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "path-app", "sbom:lock.json"), original))

		loaded, err := repo.LoadTree(ctx, nil, original.Root)
		require.NoError(t, err)

		assert.Equal(t,
			original.PathsToPURL("pkg:npm/target@1.0.0", 0),
			loaded.PathsToPURL("pkg:npm/target@1.0.0", 0))
	})

	t.Run("a deep chain terminates rather than recursing forever", func(t *testing.T) {
		children := map[string][]string{"root-ref": {purlAt(0)}}
		for i := range 300 {
			children[purlAt(i)] = []string{purlAt(i + 1)}
		}
		deep := tree(children, "deep-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "deep-app", "sbom:lock.json"), deep))

		loaded, err := repo.LoadTree(ctx, nil, deep.Root)
		require.NoError(t, err)
		assert.Equal(t, deep.Len(), loaded.Len())
	})
}

func purlAt(i int) string {
	return fmt.Sprintf("pkg:npm/dep%d@1.0.0", i)
}

func TestSBOMRepositoryDeduplicatesSubtrees(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, _, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewSBOMRepository(db)
	ctx := context.Background()

	t.Run("re-ingesting unchanged content stores no new edges", func(t *testing.T) {
		unchanged := tree(map[string][]string{
			"root-ref":        {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
		}, "stable-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "stable-app", "sbom:lock.json"), unchanged))
		afterFirst := countEdges(t, db)

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "stable-app", "sbom:lock.json"), unchanged))

		assert.Equal(t, afterFirst, countEdges(t, db), "an unchanged rescan must be a no-op")
	})

	t.Run("re-ingesting one origin replaces its pivot row rather than adding one", func(t *testing.T) {
		first := tree(map[string][]string{"root-ref": {"pkg:npm/v@1.0.0"}}, "moving-app")
		second := tree(map[string][]string{"root-ref": {"pkg:npm/v@2.0.0"}}, "moving-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "moving-app", "sbom:lock.json"), first))
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "moving-app", "sbom:lock.json"), second))

		sboms, err := repo.FindByArtifact(ctx, nil, assetVersion.AssetID, assetVersion.Name, "moving-app")
		require.NoError(t, err)
		require.Len(t, sboms, 1, "one origin is one SBOM, whatever its content history")
		assert.Equal(t, second.Root, sboms[0].RootSubtreeHash)
	})

	t.Run("two artifacts sharing a subtree store it once", func(t *testing.T) {
		shared := map[string][]string{
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.1.0"},
		}
		firstChildren := map[string][]string{"root-ref": {"pkg:golang/circl@1.6.3"}}
		secondChildren := map[string][]string{"root-ref": {"pkg:golang/circl@1.6.3"}}
		for k, v := range shared {
			firstChildren[k] = v
			secondChildren[k] = v
		}

		first := tree(firstChildren, "sharing-app-one")
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "sharing-app-one", "sbom:lock.json"), first))
		afterFirst := countEdges(t, db)

		second := tree(secondChildren, "sharing-app-two")
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "sharing-app-two", "sbom:lock.json"), second))
		afterSecond := countEdges(t, db)

		// only the second artifact's own root rows are new; the shared circl
		// subtree collides on the primary key
		assert.Equal(t, afterFirst+1, afterSecond,
			"the shared subtree must not be stored twice")
	})

	t.Run("two artifacts disagreeing about a component keep both edge sets", func(t *testing.T) {
		// the case the old last-write-wins edge table could not represent
		first := tree(map[string][]string{
			"root-ref":               {"pkg:golang/circl@9.9.9"},
			"pkg:golang/circl@9.9.9": {"pkg:golang/sys@0.1.0"},
		}, "disagree-one")
		second := tree(map[string][]string{
			"root-ref":               {"pkg:golang/circl@9.9.9"},
			"pkg:golang/circl@9.9.9": {"pkg:golang/sys@0.2.0"},
		}, "disagree-two")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "disagree-one", "sbom:lock.json"), first))
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "disagree-two", "sbom:lock.json"), second))

		loadedFirst, err := repo.LoadTree(ctx, nil, first.Root)
		require.NoError(t, err)
		loadedSecond, err := repo.LoadTree(ctx, nil, second.Root)
		require.NoError(t, err)

		assert.Contains(t, loadedFirst.ComponentIDs(), "pkg:golang/sys@0.1.0")
		assert.NotContains(t, loadedFirst.ComponentIDs(), "pkg:golang/sys@0.2.0",
			"one artifact's rescan must not rewrite what the other sees")
		assert.Contains(t, loadedSecond.ComponentIDs(), "pkg:golang/sys@0.2.0")
		assert.NotContains(t, loadedSecond.ComponentIDs(), "pkg:golang/sys@0.1.0")
	})
}

func TestSBOMRepositoryFindsAffectedSBOMs(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, _, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewSBOMRepository(db)
	ctx := context.Background()

	affected := tree(map[string][]string{
		"root-ref":        {"pkg:npm/a@1.0.0"},
		"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
		"pkg:npm/b@1.0.0": {"pkg:npm/vulnerable@1.0.0"},
	}, "affected-app")
	unaffected := tree(map[string][]string{
		"root-ref": {"pkg:npm/safe@1.0.0"},
	}, "unaffected-app")

	require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "affected-app", "sbom:lock.json"), affected))
	require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "unaffected-app", "sbom:lock.json"), unaffected))

	t.Run("walking up from a transitive component reaches its SBOM", func(t *testing.T) {
		sboms, err := repo.FindSBOMsContainingComponent(ctx, nil, "pkg:npm/vulnerable@1.0.0")
		require.NoError(t, err)

		require.Len(t, sboms, 1)
		assert.Equal(t, "affected-app", sboms[0].ArtifactName)
	})

	t.Run("walking up from a direct dependency reaches its SBOM", func(t *testing.T) {
		sboms, err := repo.FindSBOMsContainingComponent(ctx, nil, "pkg:npm/a@1.0.0")
		require.NoError(t, err)

		require.Len(t, sboms, 1)
		assert.Equal(t, "affected-app", sboms[0].ArtifactName)
	})

	t.Run("a component nobody depends on affects nothing", func(t *testing.T) {
		sboms, err := repo.FindSBOMsContainingComponent(ctx, nil, "pkg:npm/never-seen@1.0.0")
		require.NoError(t, err)
		assert.Empty(t, sboms)
	})

	t.Run("an orphaned subtree produces no phantom results", func(t *testing.T) {
		// stored, then its SBOM removed: the subtree survives but reaches no
		// root, so the upward walk must not report anything
		orphan := tree(map[string][]string{
			"root-ref": {"pkg:npm/orphaned@1.0.0"},
		}, "orphan-app")
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "orphan-app", "sbom:lock.json"), orphan))
		require.NoError(t, repo.DeleteByArtifact(ctx, nil, assetVersion.AssetID, assetVersion.Name, "orphan-app"))

		sboms, err := repo.FindSBOMsContainingComponent(ctx, nil, "pkg:npm/orphaned@1.0.0")
		require.NoError(t, err)
		assert.Empty(t, sboms, "a subtree that reaches no root is invisible")
	})
}

func TestSBOMRepositoryListsSBOMsOfAnAssetVersion(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, _, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewSBOMRepository(db)
	ctx := context.Background()

	require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "app", "sbom:package-lock.json"),
		tree(map[string][]string{"root-ref": {"pkg:npm/a@1.0.0"}}, "app")))
	require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "app", "sbom:go.mod"),
		tree(map[string][]string{"root-ref": {"pkg:golang/b@1.0.0"}}, "app")))
	require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "other-app", "sbom:go.mod"),
		tree(map[string][]string{"root-ref": {"pkg:golang/c@1.0.0"}}, "other-app")))

	t.Run("one artifact can have several origins", func(t *testing.T) {
		sboms, err := repo.FindByArtifact(ctx, nil, assetVersion.AssetID, assetVersion.Name, "app")
		require.NoError(t, err)

		require.Len(t, sboms, 2)
		assert.Equal(t, "sbom:go.mod", sboms[0].Origin)
		assert.Equal(t, "sbom:package-lock.json", sboms[1].Origin)
	})

	t.Run("scanning an asset version means fetching all of its SBOMs", func(t *testing.T) {
		sboms, err := repo.FindByAssetVersion(ctx, nil, assetVersion.AssetID, assetVersion.Name)
		require.NoError(t, err)
		assert.Len(t, sboms, 3)
	})

	t.Run("deleting one origin leaves the artifact's other SBOMs alone", func(t *testing.T) {
		require.NoError(t, repo.DeleteByOrigin(ctx, nil, assetVersion.AssetID, assetVersion.Name, "app", "sbom:go.mod"))

		sboms, err := repo.FindByArtifact(ctx, nil, assetVersion.AssetID, assetVersion.Name, "app")
		require.NoError(t, err)
		require.Len(t, sboms, 1)
		assert.Equal(t, "sbom:package-lock.json", sboms[0].Origin)
	})

	t.Run("deleting an asset version cascades to its SBOMs", func(t *testing.T) {
		doomed := models.AssetVersion{
			Name:    "doomed-branch",
			AssetID: assetVersion.AssetID,
			Slug:    "doomed-branch",
			Type:    "branch",
		}
		require.NoError(t, db.Create(&doomed).Error)

		require.NoError(t, repo.Save(ctx, nil, sbomFor(doomed, "doomed-app", "sbom:lock.json"),
			tree(map[string][]string{"root-ref": {"pkg:npm/x@1.0.0"}}, "doomed-app")))

		require.NoError(t, db.Where("asset_id = ? AND name = ?", doomed.AssetID, doomed.Name).
			Delete(&models.AssetVersion{}).Error)

		sboms, err := repo.FindByAssetVersion(ctx, nil, doomed.AssetID, doomed.Name)
		require.NoError(t, err)
		assert.Empty(t, sboms)
	})
}

func TestSBOMRepositoryCollectsGarbage(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, _, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewSBOMRepository(db)
	ctx := context.Background()

	t.Run("superseded subtrees are swept, live ones are kept", func(t *testing.T) {
		old := tree(map[string][]string{
			"root-ref":              {"pkg:npm/old-dep@1.0.0"},
			"pkg:npm/old-dep@1.0.0": {"pkg:npm/old-transitive@1.0.0"},
		}, "gc-app")
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "gc-app", "sbom:lock.json"), old))

		updated := tree(map[string][]string{
			"root-ref":              {"pkg:npm/new-dep@1.0.0"},
			"pkg:npm/new-dep@1.0.0": {"pkg:npm/new-transitive@1.0.0"},
		}, "gc-app")
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "gc-app", "sbom:lock.json"), updated))

		// the old spine is unreferenced now, but content addressing never
		// deletes on rescan, so it is still on disk until swept
		_, err := repo.LoadTree(ctx, nil, old.Root)
		require.NoError(t, err)

		deleted, err := repo.CollectGarbage(ctx, nil)
		require.NoError(t, err)
		assert.Positive(t, deleted)

		live, err := repo.LoadTree(ctx, nil, updated.Root)
		require.NoError(t, err)
		assert.Equal(t, updated.Len(), live.Len(), "the live SBOM must survive the sweep")

		swept, err := repo.LoadTree(ctx, nil, old.Root)
		require.NoError(t, err)
		assert.Zero(t, swept.Len(), "the superseded spine must be gone")
	})

	t.Run("a subtree still shared by another SBOM is kept", func(t *testing.T) {
		keptChildren := map[string][]string{
			"root-ref":                 {"pkg:npm/still-used@1.0.0"},
			"pkg:npm/still-used@1.0.0": {"pkg:npm/still-used-child@1.0.0"},
		}
		keeper := tree(keptChildren, "keeper-app")
		sharer := tree(keptChildren, "sharer-app")

		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "keeper-app", "sbom:lock.json"), keeper))
		require.NoError(t, repo.Save(ctx, nil, sbomFor(assetVersion, "sharer-app", "sbom:lock.json"), sharer))

		// drop one of the two SBOMs sharing the subtree
		require.NoError(t, repo.DeleteByArtifact(ctx, nil, assetVersion.AssetID, assetVersion.Name, "sharer-app"))

		_, err := repo.CollectGarbage(ctx, nil)
		require.NoError(t, err)

		survivor, err := repo.LoadTree(ctx, nil, keeper.Root)
		require.NoError(t, err)
		assert.Contains(t, survivor.ComponentIDs(), "pkg:npm/still-used-child@1.0.0",
			"a subtree another SBOM still reaches must not be swept")
	})

	t.Run("a sweep with nothing to collect deletes nothing", func(t *testing.T) {
		before := countEdges(t, db)

		deleted, err := repo.CollectGarbage(ctx, nil)
		require.NoError(t, err)

		assert.Zero(t, deleted)
		assert.Equal(t, before, countEdges(t, db))
	})
}
