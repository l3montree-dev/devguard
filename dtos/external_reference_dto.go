// Copyright (C) 2026 l3montree GmbH
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

type ExternalReferenceType string

const (
	ExternalReferenceTypeCycloneDX ExternalReferenceType = "cyclonedx"
	ExternalReferenceTypeCSAF      ExternalReferenceType = "csaf"
	ExternalReferenceTypeOpenVEX   ExternalReferenceType = "openvex"
	ExternalReferenceTypeUnknown   ExternalReferenceType = "unknown"
)

type ExternalReferenceDTO struct {
	AssetID string                `json:"assetId"`
	URL     string                `json:"url"`
	Type    ExternalReferenceType `json:"type"`
	Error   *string               `json:"error,omitempty"` // optional error message if the reference could not be processed
}

type CreateExternalReferenceRequest struct {
	URL              string                `json:"url" validate:"required,url"`
	Type             ExternalReferenceType `json:"type" validate:"required,oneof=cyclonedx csaf openvex"`
	CSAFPackageScope string                `json:"csafPackageScope"` // only relevant for csaf references - NEEDS TO BE A VALID PURL
}
