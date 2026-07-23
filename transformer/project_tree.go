package transformer

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func BuildArtifactIndex(artifacts []models.Artifact) map[uuid.UUID]map[string][]string {
	index := make(map[uuid.UUID]map[string][]string)
	for _, art := range artifacts {
		if index[art.AssetID] == nil {
			index[art.AssetID] = make(map[string][]string)
		}
		index[art.AssetID][art.AssetVersionName] = append(index[art.AssetID][art.AssetVersionName], art.ArtifactName)
	}
	return index
}

func BuildAssetEntries(assets []models.Asset, versionsByAssetID map[uuid.UUID][]models.AssetVersion, artifactIndex map[uuid.UUID]map[string][]string) []dtos.AssetEntryDTO {
	var entries []dtos.AssetEntryDTO
	for _, asset := range assets {
		if asset.ExternalEntityID == nil {
			continue
		}
		versions := versionsByAssetID[asset.ID]
		if len(versions) == 0 {
			continue
		}
		entry := dtos.AssetEntryDTO{AssetExternalEntityID: *asset.ExternalEntityID, AssetName: asset.Name}
		for _, av := range versions {
			entry.AssetVersions = append(entry.AssetVersions, dtos.AssetVersionEntryDTO{
				AssetVersionName: av.Name,
				Artifacts:        artifactIndex[asset.ID][av.Name],
			})
		}
		entries = append(entries, entry)
	}
	return entries
}

func BuildExternalProjectTree(
	projects []models.Project,
	subProjects []models.Project,
	assets []models.Asset,
	assetVersions []models.AssetVersion,
	artifacts []models.Artifact,
) []dtos.ProjectExternalEntityTree {
	subProjectsByParentID := make(map[uuid.UUID][]models.Project)
	for _, sp := range subProjects {
		if sp.ParentID != nil {
			subProjectsByParentID[*sp.ParentID] = append(subProjectsByParentID[*sp.ParentID], sp)
		}
	}

	assetsByProjectID := make(map[uuid.UUID][]models.Asset)
	for _, a := range assets {
		assetsByProjectID[a.ProjectID] = append(assetsByProjectID[a.ProjectID], a)
	}

	versionsByAssetID := make(map[uuid.UUID][]models.AssetVersion)
	for _, av := range assetVersions {
		versionsByAssetID[av.AssetID] = append(versionsByAssetID[av.AssetID], av)
	}

	artifactIndex := BuildArtifactIndex(artifacts)

	result := make([]dtos.ProjectExternalEntityTree, 0, len(projects))
	for _, project := range projects {
		if project.ExternalEntityID == nil {
			continue
		}
		entry := dtos.ProjectExternalEntityTree{
			ProjectExternalEntityID: *project.ExternalEntityID,
			ProjectName:             project.Name,
			Assets:                  BuildAssetEntries(assetsByProjectID[project.ID], versionsByAssetID, artifactIndex),
		}
		for _, sp := range subProjectsByParentID[project.ID] {
			if sp.ExternalEntityID == nil {
				continue
			}
			entry.SubProjects = append(entry.SubProjects, dtos.SubProjectEntryDTO{
				SubProjectExternalEntityID: *sp.ExternalEntityID,
				SubProjectName:             sp.Name,
				Assets:                     BuildAssetEntries(assetsByProjectID[sp.ID], versionsByAssetID, artifactIndex),
			})
		}
		result = append(result, entry)
	}
	return result
}
