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
	"encoding/json"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"gorm.io/datatypes"
)

func mustMarshalJSON(v any) datatypes.JSON {
	b, _ := json.Marshal(v)
	return datatypes.JSON(b)
}

func CompliancePostureToDTO(c models.CompliancePosture) dtos.CompliancePostureWithDetailsDTO {

	p := dtos.CompliancePostureWithControlDTO{
		FrameworkControlID:       c.FrameworkControlID,
		CompliancePostureID:      c.ID.String(),
		ControlID:                c.FrameworkControl.ControlID,
		Framework:                c.FrameworkControl.Framework,
		Title:                    c.FrameworkControl.Title,
		Description:              c.FrameworkControl.Description,
		Class:                    c.FrameworkControl.Class,
		Additional:               mustMarshalJSON(c.FrameworkControl.Additional),
		ParentFrameworkControlID: c.FrameworkControl.ParentFrameworkControlID,
		AssetVersionName:         c.AssetVersionName,
		AssetID:                  c.AssetID,
		ProjectID:                c.ProjectID,
		OrgID:                    &c.OrgID,
		State:                    c.State,
		TicketID:                 c.TicketID,
		TicketURL:                c.TicketURL,
	}
	events := make([]dtos.VulnEventDTO, len(c.Events))
	for i, e := range c.Events {
		events[i] = ConvertVulnEventToDto(e)
	}
	return dtos.CompliancePostureWithDetailsDTO{
		CompliancePostureWithControlDTO: p,
		Events:                          events,
	}
}
