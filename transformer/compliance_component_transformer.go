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

func ComplianceComponentToDTO(m models.ComplianceComponent) dtos.ComplianceComponentDTO {
	return dtos.ComplianceComponentDTO{
		UUID:        m.UUID.String(),
		Title:       m.Title,
		Description: m.Description,
	}
}

func ComplianceComponentImplementsControlToDTO(m models.ComplianceComponentImplementsControl) dtos.ComplianceComponentImplementsControlDTO {
	return dtos.ComplianceComponentImplementsControlDTO{
		FrameworkControlID:       m.FrameworkControlID,
		ComplianceComponentID:    m.ComplianceComponentID.String(),
		ComplianceComponentTitle: m.ComplianceComponent.Title,
		Description:              m.Description,
	}
}

func ComplianceComponentToDetailsDTO(m models.ComplianceComponent) dtos.ComplianceComponentDetailsDTO {
	dto := dtos.ComplianceComponentDetailsDTO{
		ComplianceComponentDTO: ComplianceComponentToDTO(m),
	}
	for _, ic := range m.ImplementedControls {
		dto.ImplementedControls = append(dto.ImplementedControls, ComplianceComponentImplementsControlToDTO(ic))
	}
	return dto
}

func ComplianceComponentImplementsControlStatementToDTO(m models.ComplianceComponentImplementsControlStatement) dtos.ComplianceComponentImplementsControlStatementDTO {
	component := m.ComplianceComponentImplementsControl.ComplianceComponent
	return dtos.ComplianceComponentImplementsControlStatementDTO{
		ID:                             m.ID.String(),
		CompliancePostureID:            m.CompliancePostureID.String(),
		ComplianceComponentID:          m.ComplianceComponentID.String(),
		ComplianceComponentTitle:       component.Title,
		ComplianceComponentDescription: component.Description,
		FrameworkControlID:             m.FrameworkControlID,
		ImplementationStatus:           m.ImplementationStatus,
		Description:                    m.Description,
	}
}
