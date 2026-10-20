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

type ReleaseItem struct {
	ID               uuid.UUID  `json:"id,omitempty"`
	ReleaseID        uuid.UUID  `json:"releaseId,omitempty"`
	ChildReleaseName *string    `json:"childReleaseName,omitempty"`
	ChildReleaseID   *uuid.UUID `json:"childReleaseId,omitempty" validate:"required_without=AssetID"`
	ArtifactName     *string    `json:"artifactName,omitempty"`
	AssetVersionName *string    `json:"assetVersionName,omitempty"`
	AssetID          *uuid.UUID `json:"assetId,omitempty" validate:"required_without=ChildReleaseID"`
}

type Release struct {
	ID        uuid.UUID     `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time     `json:"createdAt"`
	UpdatedAt time.Time     `json:"updatedAt"`
	Name      string        `json:"name"`
	ProjectID uuid.UUID     `json:"projectId"`
	Items     []ReleaseItem `json:"items,omitempty"`
}

// Artifact is a trimmed artifact view returned to clients. It includes the asset's name.
type Artifact struct {
	ArtifactName     string    `json:"artifactName"`
	AssetVersionName string    `json:"assetVersionName"`
	AssetID          uuid.UUID `json:"assetId"`
}

type CandidatesResponse struct {
	Artifacts []Artifact `json:"artifacts"`
	Releases  []Release  `json:"releases"`
}

// requests
type ReleaseCreateRequest struct {
	Name  string        `json:"name" validate:"required,max=256"`
	Items []ReleaseItem `json:"items,omitempty" validate:"omitempty,dive"`
}

type ReleasePatchRequest struct {
	Items []ReleaseItem `json:"items,omitempty" validate:"omitempty,dive"`
}
