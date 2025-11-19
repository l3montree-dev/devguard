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

// requests
type ReleaseCreateRequest struct {
	Name  string           `json:"name"`
	Items []ReleaseItemDTO `json:"items,omitempty"`
}

type ReleasePatchRequest struct {
	Items []ReleaseItemDTO `json:"items,omitempty"`
}
