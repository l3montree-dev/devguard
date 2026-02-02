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

package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func VEXRuleToDTO(rule models.VEXRule) dtos.VEXRuleDTO {
	return dtos.VEXRuleDTO{
		// Composite key fields
		AssetID:         rule.AssetID,
		CVEID:           rule.CVEID,
		PathPatternHash: rule.PathPatternHash,
		VexSource:       rule.VexSource,

		// Rule data
		Justification:           rule.Justification,
		MechanicalJustification: rule.MechanicalJustification,
		EventType:               rule.EventType,
		PathPattern:             dtos.PathPattern(rule.PathPattern),
		CreatedByID:             rule.CreatedByID,
		CreatedAt:               rule.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:               rule.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
