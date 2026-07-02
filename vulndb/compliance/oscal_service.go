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

package vulndb

import (
	"encoding/json"
	"fmt"
	"io"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/datatypes"
)

type AdditionalMapper func(groupTitle *string, controlProps *[]oscalTypes.Property, parts []oscalTypes.Part) map[string]interface{}

func mustMarshalJSON(v any) datatypes.JSON {
	b, _ := json.Marshal(v)
	return datatypes.JSON(b)
}

func ParseOSCALCatalog(r io.Reader) (*oscalTypes.Catalog, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading catalog: %w", err)
	}

	var schema oscalTypes.OscalCompleteSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("unmarshalling oscal catalog: %w", err)
	}

	if schema.Catalog == nil {
		return nil, fmt.Errorf("no catalog found in oscal document")
	}

	return schema.Catalog, nil
}

func ExtractControlsFromCatalog(catalog *oscalTypes.Catalog, frameworkName string, mapper AdditionalMapper) []models.FrameworkControl {
	var controls []models.FrameworkControl
	for _, g := range derefGroups(catalog.Groups) {
		controls = append(controls, extractFromGroup(g, frameworkName, mapper)...)
	}
	for _, c := range derefControls(catalog.Controls) {
		controls = append(controls, controlToFrameworkControl(c, nil, nil, frameworkName, mapper)...)
	}
	return controls
}

func extractFromGroup(g oscalTypes.Group, frameworkName string, mapper AdditionalMapper) []models.FrameworkControl {
	var controls []models.FrameworkControl
	for _, c := range derefControls(g.Controls) {
		controls = append(controls, controlToFrameworkControl(c, nil, &g.Title, frameworkName, mapper)...)
	}
	for _, sub := range derefGroups(g.Groups) {
		controls = append(controls, extractFromGroup(sub, frameworkName, mapper)...)
	}
	return controls
}

func controlToFrameworkControl(c oscalTypes.Control, parentControlID *string, groupTitle *string, frameworkName string, mapper AdditionalMapper) []models.FrameworkControl {
	parts := derefParts(c.Parts)

	// Find the statement part for the description; fall back to any part with prose.
	description := ""
	for _, p := range parts {
		if p.Name == "statement" && p.Prose != "" {
			description = p.Prose
			break
		}
	}
	if description == "" {
		for _, p := range parts {
			if p.Prose != "" {
				description = p.Prose
				break
			}
		}
	}

	var result []models.FrameworkControl

	fc := models.FrameworkControl{
		Framework:   frameworkName,
		ControlID:   c.ID,
		Title:       c.Title,
		Class:       c.Class,
		Description: description,
		Additional:  mustMarshalJSON(mapper(groupTitle, c.Props, parts)),
	}
	fc.SetID()
	if parentControlID != nil {
		fc.ParentFrameworkControlID = parentControlID
	}
	result = append(result, fc)

	for _, sub := range derefControls(c.Controls) {
		result = append(result, controlToFrameworkControl(sub, &c.ID, groupTitle, frameworkName, mapper)...)
	}
	return result
}

func derefGroups(g *[]oscalTypes.Group) []oscalTypes.Group {
	if g == nil {
		return nil
	}
	return *g
}

func derefControls(c *[]oscalTypes.Control) []oscalTypes.Control {
	if c == nil {
		return nil
	}
	return *c
}

func derefParts(p *[]oscalTypes.Part) []oscalTypes.Part {
	if p == nil {
		return nil
	}
	return *p
}

func derefProps(p *[]oscalTypes.Property) []oscalTypes.Property {
	if p == nil {
		return nil
	}
	return *p
}
