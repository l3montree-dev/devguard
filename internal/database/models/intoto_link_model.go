// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

import "github.com/google/uuid"

type InTotoLink struct {
	// this is used to identify the link afterwards.
	// for the post-commit link this is the commit hash
	OpaqueIdentifier string `json:"opaqueIdentifier" gorm:"column:opaque_identifier;primaryKey"`

	// the real link payload
	Payload string `json:"payload" gorm:"column:payload"`

	PAT   PAT   `json:"pat" gorm:"foreignKey:PatID;constraint:OnDelete:CASCADE;"`
	Asset Asset `gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE;"`

	PatID   uuid.UUID `json:"patId" gorm:"column:pat_id;"`
	AssetID uuid.UUID `json:"assetId" gorm:"column:asset_id;primaryKey"`
}

func (InTotoLink) TableName() string {
	return "in_toto_links"
}
