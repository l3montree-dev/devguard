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

package dtos

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
)

type ReleaseItemDTO struct {
	ID               uuid.UUID  `json:"id,omitempty"`
	ReleaseID        uuid.UUID  `json:"releaseId,omitempty"`
	ChildReleaseName *string    `json:"childReleaseName,omitempty"`
	ChildReleaseID   *uuid.UUID `json:"childReleaseId,omitempty"`
	ArtifactName     *string    `json:"artifactName,omitempty"`
	AssetVersionName *string    `json:"assetVersionName,omitempty"`
	AssetID          *uuid.UUID `json:"assetId,omitempty"`
}

type ReleaseDTO struct {
	ID        uuid.UUID        `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time        `json:"createdAt"`
	UpdatedAt time.Time        `json:"updatedAt"`
	Name      string           `json:"name"`
	ProjectID uuid.UUID        `json:"projectId"`
	Items     []ReleaseItemDTO `json:"items,omitempty"`
}

func ReleaseItemToDTO(i models.ReleaseItem) ReleaseItemDTO {
	return ReleaseItemDTO{
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

// ArtifactDTO is a trimmed artifact view returned to clients. It includes the asset's name.
type ArtifactDTO struct {
	ArtifactName     string    `json:"artifactName"`
	AssetVersionName string    `json:"assetVersionName"`
	AssetID          uuid.UUID `json:"assetId"`
}

type CandidatesResponseDTO struct {
	Artifacts []ArtifactDTO `json:"artifacts"`
	Releases  []ReleaseDTO  `json:"releases"`
}

func ReleaseToDTO(r models.Release) ReleaseDTO {
	dto := ReleaseDTO{
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

// requests
type ReleaseCreateRequest struct {
	Name  string           `json:"name"`
	Items []ReleaseItemDTO `json:"items,omitempty"`
}

type ReleasePatchRequest struct {
	Items []ReleaseItemDTO `json:"items,omitempty"`
}

func (r ReleaseCreateRequest) ToModel(projectID uuid.UUID) models.Release {
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

func (r ReleasePatchRequest) ApplyToModel(rel *models.Release) {
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
