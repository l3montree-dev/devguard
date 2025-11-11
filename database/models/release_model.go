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

package models

import (
	"time"

	"github.com/google/uuid"
)

type Release struct {
	ID        uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Name      string    `json:"name" gorm:"not null;type:text;"`
	ProjectID uuid.UUID `json:"projectId" gorm:"index;type:uuid"`
	Project   Project   `json:"project" gorm:"foreignKey:ProjectID;references:ID;constraint:OnDelete:CASCADE;"`

	// parent → children
	Items []ReleaseItem `json:"items" gorm:"foreignKey:ReleaseID;constraint:OnDelete:CASCADE;"`

	// back reference → where this release is included as a child
	ParentItems []ReleaseItem `json:"parentItems" gorm:"foreignKey:ChildReleaseID;constraint:OnDelete:CASCADE;"`
}

func (m Release) TableName() string {
	return "releases"
}

type ReleaseItem struct {
	ID        uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	ReleaseID uuid.UUID `gorm:"index;type:uuid"` // parent release
	Release   Release   `gorm:"foreignKey:ReleaseID;constraint:OnDelete:CASCADE;"`

	ChildReleaseID *uuid.UUID `gorm:"index;type:uuid"`
	ChildRelease   *Release   `gorm:"foreignKey:ChildReleaseID;references:ID;constraint:OnDelete:CASCADE;"`

	// composite foreign key to artifacts (ArtifactName, AssetVersionName, AssetID)
	ArtifactName     *string    `gorm:"index;type:text"`
	AssetVersionName *string    `gorm:"index;type:text"`
	AssetID          *uuid.UUID `gorm:"index;type:uuid"`
	Artifact         *Artifact  `gorm:"foreignKey:ArtifactName,AssetVersionName,AssetID;references:ArtifactName,AssetVersionName,AssetID;constraint:OnDelete:CASCADE;"`
}
