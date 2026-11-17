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

package compliance

import (
	"encoding/json"
	"fmt"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
)

func ParseComponentDefinition(data []byte) (string, []models.ComplianceComponent, error) {
	def, err := parseOSCALComponentDefinition(data)
	if err != nil {
		return "", nil, err
	}
	components, err := extractComplianceComponents(def)
	if err != nil {
		return "", nil, err
	}
	return def.Metadata.Title, components, nil
}

func parseOSCALComponentDefinition(data []byte) (*oscalTypes.ComponentDefinition, error) {
	var schema oscalTypes.OscalCompleteSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("unmarshalling oscal component definition: %w", err)
	}

	if schema.ComponentDefinition == nil {
		return nil, fmt.Errorf("no component-definition found in oscal document")
	}

	return schema.ComponentDefinition, nil
}

func extractComplianceComponents(def *oscalTypes.ComponentDefinition) ([]models.ComplianceComponent, error) {
	var components []models.ComplianceComponent

	if def.Components == nil {
		return components, nil
	}

	for _, c := range *def.Components {
		oscalUUID, err := uuid.Parse(c.UUID)
		if err != nil {
			return nil, fmt.Errorf("invalid component uuid %q: %w", c.UUID, err)
		}

		component := models.ComplianceComponent{
			UUID:        oscalUUID,
			Title:       c.Title,
			Description: c.Description,
		}

		if c.ControlImplementations != nil {
			for _, impl := range *c.ControlImplementations {
				for _, ir := range impl.ImplementedRequirements {
					component.ImplementedControls = append(component.ImplementedControls, models.ComplianceComponentImplementsControl{
						FrameworkControlID: fmt.Sprintf("%s:%s", impl.Source, ir.ControlId),
						Description:        ir.Description,
					})
				}
			}
		}

		components = append(components, component)
	}

	return components, nil
}
