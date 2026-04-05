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

func ConvertVulnEventDetailToDto(e models.VulnEventDetail) dtos.VulnEventDTO {
	return dtos.VulnEventDTO{
		ID:                       e.ID,
		Type:                     e.Type,
		VulnID:                   e.VulnID,
		VulnType:                 e.VulnType,
		UserID:                   e.UserID,
		Justification:            e.Justification,
		MechanicalJustification:  e.MechanicalJustification,
		ArbitraryJSONData:        e.GetArbitraryJSONData(),
		CreatedAt:                e.CreatedAt,
		OriginalAssetVersionName: e.OriginalAssetVersionName,
		VulnerabilityName:        e.CVEID,
		PackageName:              e.ComponentPurl,
		URI:                      e.URI,
		CreatedByVexRule:         e.CreatedByVexRule,
	}
}

func ConvertVulnEventsToDtos(events []models.VulnEventDetail) []dtos.VulnEventDTO {
	var result []dtos.VulnEventDTO
	for _, e := range events {
		result = append(result, ConvertVulnEventDetailToDto(e))
	}
	return result
}

func ConvertVulnEventToDto(event models.VulnEvent) dtos.VulnEventDTO {
	return dtos.VulnEventDTO{
		ID:                      event.ID,
		Type:                    event.Type,
		VulnID:                  event.VulnID,
		VulnType:                event.VulnType,
		UserID:                  event.UserID,
		Justification:           event.Justification,
		MechanicalJustification: event.MechanicalJustification,
		ArbitraryJSONData:       event.GetArbitraryJSONData(),
		CreatedAt:               event.CreatedAt,
		CreatedByVexRule:        event.CreatedByVexRule,
	}
}
