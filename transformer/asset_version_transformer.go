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

func AssetVersionModelToDTO(assetVersion models.AssetVersion) dtos.AssetVersionDTO {
	return dtos.AssetVersionDTO{
		CreatedAt:      assetVersion.CreatedAt.String(),
		UpdatedAt:      assetVersion.UpdatedAt.String(),
		Name:           assetVersion.Name,
		AssetID:        assetVersion.AssetID.String(),
		DefaultBranch:  assetVersion.DefaultBranch,
		Slug:           assetVersion.Slug,
		Type:           string(assetVersion.Type),
		SigningPubKey:  assetVersion.SigningPubKey,
		Metadata:       assetVersion.Metadata,
		LastAccessedAt: assetVersion.LastAccessedAt.String(),
	}
}
