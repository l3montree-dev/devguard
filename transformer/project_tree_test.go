package transformer_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/stretchr/testify/assert"
)

func TestBuildArtifactIndex(t *testing.T) {
	assetID := uuid.New()

	artifacts := []models.Artifact{
		{AssetID: assetID, AssetVersionName: "v1.0", ArtifactName: "app"},
		{AssetID: assetID, AssetVersionName: "v1.0", ArtifactName: "sidecar"},
		{AssetID: assetID, AssetVersionName: "v2.0", ArtifactName: "app"},
	}

	index := transformer.BuildArtifactIndex(artifacts)

	assert.ElementsMatch(t, []string{"app", "sidecar"}, index[assetID]["v1.0"])
	assert.Equal(t, []string{"app"}, index[assetID]["v2.0"])
}

func TestBuildArtifactIndexEmpty(t *testing.T) {
	assert.Empty(t, transformer.BuildArtifactIndex(nil))
}

func TestBuildAssetEntries(t *testing.T) {
	assetID := uuid.New()

	assets := []models.Asset{
		{Model: models.Model{ID: assetID}, Name: "my-app", ExternalEntityID: new("ext-123")},
	}
	versions := map[uuid.UUID][]models.AssetVersion{
		assetID: {{Name: "v1.0", AssetID: assetID}},
	}
	artifactIndex := map[uuid.UUID]map[string][]string{
		assetID: {"v1.0": {"app", "sidecar"}},
	}

	entries := transformer.BuildAssetEntries(assets, versions, artifactIndex)

	assert.Len(t, entries, 1)
	assert.Equal(t, "ext-123", entries[0].AssetExternalEntityID)
	assert.Equal(t, "my-app", entries[0].AssetName)
	assert.Len(t, entries[0].AssetVersions, 1)
	assert.Equal(t, "v1.0", entries[0].AssetVersions[0].AssetVersionName)
	assert.ElementsMatch(t, []string{"app", "sidecar"}, entries[0].AssetVersions[0].Artifacts)
}

func TestBuildAssetEntriesSkipsNilExternalEntityID(t *testing.T) {
	assetID := uuid.New()
	assets := []models.Asset{
		{Model: models.Model{ID: assetID}, Name: "internal", ExternalEntityID: nil},
	}
	entries := transformer.BuildAssetEntries(assets, map[uuid.UUID][]models.AssetVersion{}, map[uuid.UUID]map[string][]string{})
	assert.Empty(t, entries)
}

func TestBuildAssetEntriesSkipsAssetsWithNoVersions(t *testing.T) {
	assetID := uuid.New()
	assets := []models.Asset{
		{Model: models.Model{ID: assetID}, Name: "app", ExternalEntityID: new("ext-1")},
	}
	entries := transformer.BuildAssetEntries(assets, map[uuid.UUID][]models.AssetVersion{}, map[uuid.UUID]map[string][]string{})
	assert.Empty(t, entries)
}

func TestBuildExternalProjectTree(t *testing.T) {
	parentID := uuid.New()
	projectID := uuid.New()
	subProjectID := uuid.New()
	assetID := uuid.New()
	subAssetID := uuid.New()

	projects := []models.Project{
		{Model: models.Model{ID: projectID}, Name: "proj", ParentID: new(parentID), ExternalEntityID: new("proj-ext")},
	}
	subProjects := []models.Project{
		{Model: models.Model{ID: subProjectID}, Name: "sub", ParentID: new(projectID), ExternalEntityID: new("sub-ext")},
	}
	assets := []models.Asset{
		{Model: models.Model{ID: assetID}, Name: "asset", ProjectID: projectID, ExternalEntityID: new("asset-ext")},
		{Model: models.Model{ID: subAssetID}, Name: "sub-asset", ProjectID: subProjectID, ExternalEntityID: new("sub-asset-ext")},
	}
	versions := []models.AssetVersion{
		{Name: "v1", AssetID: assetID},
		{Name: "v1", AssetID: subAssetID},
	}
	artifacts := []models.Artifact{
		{AssetID: assetID, AssetVersionName: "v1", ArtifactName: "app"},
		{AssetID: subAssetID, AssetVersionName: "v1", ArtifactName: "sub-app"},
	}

	result := transformer.BuildExternalProjectTree(projects, subProjects, assets, versions, artifacts)

	assert.Len(t, result, 1)
	tree := result[0]
	assert.Equal(t, "proj-ext", tree.ProjectExternalEntityID)
	assert.Equal(t, "proj", tree.ProjectName)

	assert.Len(t, tree.Assets, 1)
	assert.Equal(t, "asset-ext", tree.Assets[0].AssetExternalEntityID)
	assert.Equal(t, []string{"app"}, tree.Assets[0].AssetVersions[0].Artifacts)

	assert.Len(t, tree.SubProjects, 1)
	assert.Equal(t, "sub-ext", tree.SubProjects[0].SubProjectExternalEntityID)
	assert.Len(t, tree.SubProjects[0].Assets, 1)
	assert.Equal(t, "sub-asset-ext", tree.SubProjects[0].Assets[0].AssetExternalEntityID)
}

func TestBuildExternalProjectTreeSkipsProjectsWithNilExternalEntityID(t *testing.T) {
	projects := []models.Project{
		{Model: models.Model{ID: uuid.New()}, Name: "internal", ExternalEntityID: nil},
	}
	result := transformer.BuildExternalProjectTree(projects, nil, nil, nil, nil)
	assert.Empty(t, result)
}

func TestBuildExternalProjectTreeSkipsSubProjectsWithNilExternalEntityID(t *testing.T) {
	projectID := uuid.New()
	projects := []models.Project{
		{Model: models.Model{ID: projectID}, Name: "proj", ExternalEntityID: new("proj-ext")},
	}
	subProjects := []models.Project{
		{Model: models.Model{ID: uuid.New()}, Name: "internal-sub", ParentID: new(projectID), ExternalEntityID: nil},
	}
	result := transformer.BuildExternalProjectTree(projects, subProjects, nil, nil, nil)
	assert.Len(t, result, 1)
	assert.Empty(t, result[0].SubProjects)
}

func TestBuildExternalProjectTreeEmptyInputs(t *testing.T) {
	result := transformer.BuildExternalProjectTree(nil, nil, nil, nil, nil)
	assert.Equal(t, []dtos.ProjectExternalEntityTree{}, result)
}
