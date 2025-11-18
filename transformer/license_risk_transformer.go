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

func LicenseRiskToDTO(f models.LicenseRisk) dtos.LicenseRiskDTO {
	artifacts := make([]dtos.LicenseRiskArtifactDTO, len(f.Artifacts))
	for i, artifact := range f.Artifacts {
		artifacts[i] = dtos.LicenseRiskArtifactDTO{
			ArtifactName:     artifact.ArtifactName,
			AssetVersionName: artifact.AssetVersionName,
			AssetID:          artifact.AssetID.String(),
		}
	}

	return dtos.LicenseRiskDTO{
		ID:                   f.ID,
		Artifacts:            artifacts,
		Message:              f.Message,
		AssetVersionName:     f.AssetVersionName,
		AssetID:              f.AssetID.String(),
		State:                f.State,
		CreatedAt:            f.CreatedAt,
		TicketID:             f.TicketID,
		TicketURL:            f.TicketURL,
		ManualTicketCreation: f.ManualTicketCreation,
		FinalLicenseDecision: dtos.BeautifyFinalLicenseDecision(f.FinalLicenseDecision),
		ComponentPurl:        f.ComponentPurl,
		Component:            ComponentModelToDTO(f.Component),
	}
}
