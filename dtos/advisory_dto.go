// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package dtos

import "github.com/google/uuid"

type AdvisoryCreate struct {
	Title            string            `json:"title" validate:"required"`
	Description      string            `json:"description" validate:"required"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
	Severity         string            `json:"severity"`
	VectorString     string            `json:"vectorString"`
	AssetID          uuid.UUID         `json:"assetID"`
}
type AdvisoryUpdate struct {
	Title            *string           `json:"title"`
	Description      *string           `json:"description"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
	Severity         *string           `json:"severity"`
	VectorString     *string           `json:"vectorString"`
	AssetID          *uuid.UUID        `json:"assetID"`
	Visibility       *string           `json:"visibility"`
}

type AdvisoryDTO struct {
	ID               uuid.UUID         `json:"id"`
	Title            string            `json:"title" validate:"required"`
	Description      string            `json:"description" validate:"required"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
	Severity         string            `json:"severity"`
	VectorString     string            `json:"vectorString"`
	AssetID          uuid.UUID         `json:"assetID"`
	Visibility       string            `json:"visibility"`
}

type AffectedPackage struct {
	ID               uuid.UUID `json:"id,omitempty"`
	Ecosystem        string    `json:"ecosystem"`
	PackageName      string    `json:"packageName"`
	SemverIntroduced *string   `json:"semverStart"`
	SemverFixed      *string   `json:"semverEnd"`
}