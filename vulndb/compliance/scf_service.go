// Copyright (C) 2026 l3montree GmbH
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
	"bytes"
	_ "embed"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/l3montree-dev/devguard/database/models"
)

//go:embed SCF.json
var scfCatalogJSON []byte

func LoadSCFControls() ([]models.FrameworkControl, error) {
	catalog, err := ParseOSCALCatalog(bytes.NewReader(scfCatalogJSON))
	if err != nil {
		return nil, err
	}
	return ExtractControlsFromCatalog(catalog, "SCF", scfAdditionalMapper), nil
}

func scfAdditionalMapper(groupTitle *string, controlProps *[]oscalTypes.Property, parts []oscalTypes.Part) map[string]any {
	additional := make(map[string]any)

	assessmentObjective := []oscalTypes.Part{}

	if groupTitle != nil {
		additional["group_title"] = *groupTitle
	}

	for _, p := range parts {
		if p.Name == "assessment-objective" {
			assessmentObjective = append(assessmentObjective, p)
		}
	}
	additional["assessment_objective"] = assessmentObjective

	for _, prop := range derefProps(controlProps) {
		switch prop.Name {
		case "weight":
			additional["importance"] = prop
		}
	}

	return additional
}
