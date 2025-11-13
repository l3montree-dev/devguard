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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func ReleaseItemToDTO(i models.ReleaseItem) dtos.ReleaseItemDTO {
	return dtos.ReleaseItemDTO{
		ID:               i.ID,
		ReleaseID:        i.ReleaseID,
		ChildReleaseID:   i.ChildReleaseID,
		ArtifactName:     i.ArtifactName,
		AssetVersionName: i.AssetVersionName,
		AssetID:          i.AssetID,
		ChildReleaseName: func() *string {
			if i.ChildRelease != nil {
				return &i.ChildRelease.Name
			}
			return nil
		}(),
	}
}

func ReleaseToDTO(r models.Release) dtos.ReleaseDTO {
	dto := dtos.ReleaseDTO{
		ID:        r.ID,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
		ProjectID: r.ProjectID,
		Name:      r.Name,
	}

	for _, it := range r.Items {
		dto.Items = append(dto.Items, ReleaseItemToDTO(it))
	}

	return dto
}

func ReleaseCreateRequestToModel(r dtos.ReleaseCreateRequest, projectID uuid.UUID) models.Release {
	rel := models.Release{
		Name:      r.Name,
		ProjectID: projectID,
	}

	for _, it := range r.Items {
		rel.Items = append(rel.Items, models.ReleaseItem{
			ID:               it.ID,
			ChildReleaseID:   it.ChildReleaseID,
			ArtifactName:     it.ArtifactName,
			AssetVersionName: it.AssetVersionName,
			AssetID:          it.AssetID,
		})
	}

	return rel
}

func ApplyReleasePatchRequestToModel(r dtos.ReleasePatchRequest, rel *models.Release) {
	// naive full replace of items for now
	var items []models.ReleaseItem
	for _, it := range r.Items {
		items = append(items, models.ReleaseItem{
			ID:               it.ID,
			ReleaseID:        rel.ID,
			ChildReleaseID:   it.ChildReleaseID,
			ArtifactName:     it.ArtifactName,
			AssetVersionName: it.AssetVersionName,
			AssetID:          it.AssetID,
		})
	}
	rel.Items = items
}
