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
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
)

type FrameworkName string

const (
	ISO27001                            FrameworkName = "ISO27001"
	GrundschutzPlusPlus                 FrameworkName = "Grundschutz++"
	BSIAnforderungenZumRisikomanagement FrameworkName = "BSI-Anforderungen-zum-Risikomanagement"
	Lieferkettensicherheit              FrameworkName = "Lieferkettensicherheit"
	SCF                                 FrameworkName = "SCF"
)

//go:embed oscal/catalogs/ISO27001-AnnexA-to-GS++-mapping_collection.json
var iso27001ToGSPlusPlusMappingCollectionJSON []byte

type MappingCollection struct {
	MappingCollection struct {
		Mappings []Mapping `json:"mappings"`
	} `json:"mapping-collection"`
}
type Mapping struct {
	SourceResource Resource `json:"source-resource"`
	TargetResource Resource `json:"target-resource"`
	Maps           []Map    `json:"maps"`
}
type Map struct {
	UUID         string   `json:"uuid"`
	Relationship string   `json:"relationship"`
	Sources      []Source `json:"sources"`
	Targets      []Target `json:"targets"`
}

type Source struct {
	Type  string `json:"type"`
	IDRef string `json:"id-ref"`
}
type Target struct {
	Type  string `json:"type"`
	IDRef string `json:"id-ref"`
}
type Resource struct {
	Type string `json:"type"`
	Href string `json:"href"`
}

func loadISO27001ToGSPlusPlusMappingCollection() ([]models.MappedControl, error) {
	var results []models.MappedControl

	mappingCollection, err := parseOSCALMappingCollection(bytes.NewReader(iso27001ToGSPlusPlusMappingCollectionJSON))
	if err != nil {
		return nil, err
	}

	for _, mapping := range mappingCollection.MappingCollection.Mappings {
		if mapping.SourceResource.Type != "catalog" || mapping.TargetResource.Type != "catalog" {
			continue // Skip mappings that are not between catalogs
		}
		if mapping.SourceResource.Href != "ISO27001-AnnexA-catalog.json" || mapping.TargetResource.Href != "BSI-Methodik-Grundschutz++-catalog.json" {
			continue // Skip mappings that are not between the expected catalogs
		}

		sourceFramework := ISO27001
		targetFramework := GrundschutzPlusPlus

		mappedControls, err := extractMappingsFromMappingCollection(mapping.Maps, sourceFramework, targetFramework)
		if err != nil {
			return nil, fmt.Errorf("error extracting mappings from mapping collection: %w", err)
		}
		results = append(results, mappedControls...)

		//calculate the reverse mapping
		var reverseMappedControls []models.MappedControl
		for _, mc := range mappedControls {
			relationship := mc.Relationship
			switch mc.Relationship {
			case "superset-of":
				relationship = "subset-of"
			case "subset-of":
				relationship = "superset-of"
			}

			reverseMappedControls = append(reverseMappedControls, models.MappedControl{
				FrameworkControlID: fmt.Sprintf("%s:%s", targetFramework, mc.RelatedControlID),
				RelatedFramework:   string(sourceFramework),
				RelatedControlID:   strings.Split(mc.FrameworkControlID, ":")[1], // Extract the control ID from the FrameworkControlID
				Relationship:       relationship,
			})
		}
		results = append(results, reverseMappedControls...)

	}

	return results, nil
}

func parseOSCALMappingCollection(r io.Reader) (*MappingCollection, error) {
	var mappingCollection MappingCollection

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &mappingCollection)
	if err != nil {
		return nil, err
	}

	return &mappingCollection, nil
}

func extractMappingsFromMappingCollection(maps []Map, sourceFramework FrameworkName, targetFramework FrameworkName) ([]models.MappedControl, error) {
	var mappedControls []models.MappedControl

	for _, mapping := range maps {
		for _, source := range mapping.Sources {
			if source.Type != "control" {
				return nil, fmt.Errorf("source type is not 'control' for mapping %s", mapping.UUID)
			}
			for _, target := range mapping.Targets {
				if target.Type != "control" {
					return nil, fmt.Errorf("target type is not 'control' for mapping %s", mapping.UUID)
				}

				mappedControl := models.MappedControl{
					FrameworkControlID: fmt.Sprintf("%s:%s", sourceFramework, source.IDRef),
					RelatedFramework:   string(targetFramework),
					RelatedControlID:   target.IDRef,
					Relationship:       mapping.Relationship,
				}

				mappedControls = append(mappedControls, mappedControl)
			}
		}

	}
	return mappedControls, nil
}
