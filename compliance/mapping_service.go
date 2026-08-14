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
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
)

type frameworkName string

const (
	iso27001                            frameworkName = "ISO27001"
	grundschutzPlusPlus                 frameworkName = "Grundschutz++"
	grundschutz                         frameworkName = "Grundschutz"
	bsiAnforderungenZumRisikomanagement frameworkName = "BSI-Anforderungen-zum-Risikomanagement"
	lieferkettensicherheit              frameworkName = "Lieferkettensicherheit"
	scf                                 frameworkName = "SCF"
)

//go:embed oscal/mappings/ISO27001-AnnexA-to-GS++-mapping_collection.json
var iso27001ToGSPlusPlusMappingCollectionJSON []byte

//go:embed oscal/mappings/ITGS-to-GS++-mapping_collection.json
var grundschutzToGSPlusPlusMappingCollectionJSON []byte

type mappingCollection struct {
	MappingCollection struct {
		Mappings []mapping `json:"mappings"`
	} `json:"mapping-collection"`
}
type mapping struct {
	SourceResource resource     `json:"source-resource"`
	TargetResource resource     `json:"target-resource"`
	Maps           []mappingMap `json:"maps"`
}
type mappingMap struct {
	UUID         string   `json:"uuid"`
	Relationship string   `json:"relationship"`
	Sources      []source `json:"sources"`
	Targets      []target `json:"targets"`
}

type source struct {
	Type  string `json:"type"`
	IDRef string `json:"id-ref"`
}
type target struct {
	Type  string `json:"type"`
	IDRef string `json:"id-ref"`
}
type resource struct {
	Type string `json:"type"`
	Href string `json:"href"`
}

func loadGrundschutzToGSPlusPlusMappingCollection() ([]models.MappedControl, error) {
	var results []models.MappedControl
	var mappingCollection mappingCollection

	if err := json.NewDecoder(bytes.NewReader(grundschutzToGSPlusPlusMappingCollectionJSON)).Decode(&mappingCollection); err != nil {
		return nil, err
	}

	for _, mapping := range mappingCollection.MappingCollection.Mappings {
		mappedControls, err := extractMappingsFromMappingCollection(mapping.Maps, grundschutz, grundschutzPlusPlus)
		if err != nil {
			return nil, fmt.Errorf("error extracting mappings from mapping collection: %w", err)
		}
		results = append(results, mappedControls...)
	}
	return results, nil
}

func loadISO27001ToGSPlusPlusMappingCollection() ([]models.MappedControl, error) {
	var results []models.MappedControl
	var mappingCollection mappingCollection

	if err := json.NewDecoder(bytes.NewReader(iso27001ToGSPlusPlusMappingCollectionJSON)).Decode(&mappingCollection); err != nil {
		return nil, err
	}

	for _, mapping := range mappingCollection.MappingCollection.Mappings {
		if mapping.SourceResource.Type != "catalog" || mapping.TargetResource.Type != "catalog" {
			continue // Skip mappings that are not between catalogs
		}
		if mapping.SourceResource.Href != "ISO27001-AnnexA-catalog.json" || mapping.TargetResource.Href != "BSI-Methodik-Grundschutz++-catalog.json" {
			continue // Skip mappings that are not between the expected catalogs
		}

		sourceFramework := iso27001
		targetFramework := grundschutzPlusPlus

		mappedControls, err := extractMappingsFromMappingCollection(mapping.Maps, sourceFramework, targetFramework)
		if err != nil {
			return nil, fmt.Errorf("error extracting mappings from mapping collection: %w", err)
		}
		results = append(results, mappedControls...)
	}

	return results, nil
}

func extractMappingsFromMappingCollection(maps []mappingMap, sourceFramework frameworkName, targetFramework frameworkName) ([]models.MappedControl, error) {
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
	//calculate the reverse mapping
	// since it is really not a lot, we are precaculating it here to avoid implementing any logic in the u
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
	return append(mappedControls, reverseMappedControls...), nil
}
