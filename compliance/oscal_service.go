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
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/defenseunicorns/go-oscal/src/pkg/validation"
	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/datatypes"
)

type additionalMapper func(groupTitle *string, controlProps *[]oscalTypes.Property, parts []oscalTypes.Part) map[string]any

func mustMarshalJSON(v any) datatypes.JSON {
	b, _ := json.Marshal(v)
	return datatypes.JSON(b)
}

func parseOSCALCatalog(r io.Reader) (*oscalTypes.Catalog, error) {
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

func ParseCatalog(data []byte) (string, []models.FrameworkControl, error) {
	catalog, err := parseOSCALCatalog(bytes.NewReader(data))
	if err != nil {
		return "", nil, err
	}
	return catalog.Metadata.Title, extractControlsFromCatalog(catalog, grundschutzAdditionalMapper), nil
}

func extractControlsFromCatalog(catalog *oscalTypes.Catalog, mapper additionalMapper) []models.FrameworkControl {
	ctx := newResolveContext(catalog)

	var controls []models.FrameworkControl
	for _, g := range deref(catalog.Groups) {
		controls = append(controls, extractFromGroup(nil, g, mapper, ctx)...)
	}
	for _, c := range deref(catalog.Controls) {
		controls = append(controls, controlToFrameworkControl(c, nil, nil, mapper, ctx)...)
	}
	return controls
}

func extractFromGroup(parentGroupTitle *string, g oscalTypes.Group, mapper additionalMapper, ctx *resolveContext) []models.FrameworkControl {
	groupTitle := &g.Title
	if parentGroupTitle != nil {
		combined := fmt.Sprintf("%s / %s", *parentGroupTitle, *groupTitle)
		groupTitle = &combined
	}

	var controls []models.FrameworkControl
	for _, c := range deref(g.Controls) {
		controls = append(controls, controlToFrameworkControl(c, nil, groupTitle, mapper, ctx)...)
	}
	for _, sub := range deref(g.Groups) {
		controls = append(controls, extractFromGroup(groupTitle, sub, mapper, ctx)...)
	}
	return controls
}

func controlToFrameworkControl(c oscalTypes.Control, parentControlID *string, groupTitle *string, mapper additionalMapper, ctx *resolveContext) []models.FrameworkControl {
	parts := deref(c.Parts)

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
	description = resolveInserts(description, ctx)

	var result []models.FrameworkControl

	var additional map[string]any
	if mapper != nil {
		additional = mapper(groupTitle, c.Props, parts)
	}

	fc := models.FrameworkControl{
		ControlID:       c.ID,
		Title:           c.Title,
		Class:           c.Class,
		Description:     description,
		Importance:      importanceString(additional["importance"]),
		SecurityLevel:   importanceString(additional["security_level"]),
		Additional:      mustMarshalJSON(additional),
		ParentControlID: parentControlID,
	}
	fc.ControlHash = fc.CalculateHash()
	result = append(result, fc)

	for _, sub := range deref(c.Controls) {
		result = append(result, controlToFrameworkControl(sub, &c.ID, groupTitle, mapper, ctx)...)
	}
	return result
}

func importanceString(v any) string {
	switch p := v.(type) {
	case string:
		return p
	case newProperty:
		return p.Value
	case oscalTypes.Property:
		return p.Value
	default:
		return ""
	}
}

func deref[T any](g *[]T) []T {
	if g == nil {
		return nil
	}
	return *g
}

// schema matching its detected model type and version.
func ValidateOSCAL(oscalDoc any) error {
	validator, err := validation.NewValidator(oscalDoc)
	if err != nil {
		return err
	}
	return validator.Validate()
}
