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

type AdvisoryCreateRequest struct {
	Title            string            `json:"title" validate:"required,max=256"`
	Description      string            `json:"description" validate:"required,max=4000"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
	Severity         string            `json:"severity" validate:"max=256"`
	VectorString     string            `json:"vectorString" validate:"max=256"`
	AssetID          uuid.UUID         `json:"assetID"`
}
type AdvisoryUpdateRequest struct {
	Title            *string           `json:"title" validate:"omitempty,max=256"`
	Description      *string           `json:"description" validate:"omitempty,max=4000"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
	Severity         *string           `json:"severity" validate:"omitempty,max=256"`
	VectorString     *string           `json:"vectorString" validate:"omitempty,max=256"`
	AssetID          *uuid.UUID        `json:"assetID"`
}

type Advisory struct {
	ID               uuid.UUID         `json:"id"`
	Title            string            `json:"title" validate:"required"`
	Description      string            `json:"description" validate:"required"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
	Severity         string            `json:"severity"`
	VectorString     string            `json:"vectorString"`
	AssetID          uuid.UUID         `json:"assetID"`
	State            VulnState         `json:"state"`
}

type AffectedPackage struct {
	ID                uuid.UUID `json:"id,omitempty"`
	Ecosystem         string    `json:"ecosystem"`
	PackageName       string    `json:"packageName"`
	VersionIntroduced *string   `json:"versionStart"`
	VersionFixed      *string   `json:"versionEnd"`
}
