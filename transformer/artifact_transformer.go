// Copyright (C) 2025 l3montree GmbH
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

package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

// the asset version name is not stored on the artifact, so AssetVersion needs to be preloaded
func ArtifactModelToDTO(artifact models.Artifact) dtos.Artifact {
	return ArtifactInAssetVersionToDTO(artifact, artifact.AssetVersion.Name)
}

func ArtifactInAssetVersionToDTO(artifact models.Artifact, assetVersionName string) dtos.Artifact {
	return dtos.Artifact{
		ID:               artifact.ID,
		ArtifactName:     artifact.ArtifactName,
		AssetVersionID:   artifact.AssetVersionID,
		AssetVersionName: assetVersionName,
		AssetID:          artifact.AssetID,
	}
}

func ArtifactsInAssetVersionToDTO(artifacts []models.Artifact, assetVersionName string) []dtos.Artifact {
	result := make([]dtos.Artifact, len(artifacts))
	for i, artifact := range artifacts {
		result[i] = ArtifactInAssetVersionToDTO(artifact, assetVersionName)
	}
	return result
}
