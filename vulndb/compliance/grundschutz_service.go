package vulndb

import (
	"bytes"
	_ "embed"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/l3montree-dev/devguard/database/models"
)

//go:embed Grundschutz++-catalog.json
var grundschutzCatalogJSON []byte

func grundschutzAdditionalMapper(groupTitle *string, controlProps *[]oscalTypes.Property, parts []oscalTypes.Part) map[string]interface{} {
	additional := make(map[string]interface{})
	if groupTitle != nil {
		additional["group_title"] = *groupTitle
	}
	for _, prop := range derefProps(controlProps) {
		switch prop.Name {
		case "sec_level":
			additional["security_level"] = prop
		case "effort_level":
			additional["effort_level"] = prop
		}

	}
	for _, p := range parts {
		if p.Name == "guidance" && p.Prose != "" {
			additional["guidance"] = p.Prose
		}
		if p.Name == "statement" {
			for _, prop := range derefProps(p.Props) {
				switch prop.Name {
				case "modal_verb":
					additional["importance"] = prop
				case "action_word":
					additional["word_definition"] = prop
				case "result":
					additional["result"] = prop
				case "result_specification":
					additional["result_specification"] = prop
				}
			}
		}
	}
	return additional
}

func LoadGrundschutzControls() ([]models.FrameworkControl, error) {
	catalog, err := ParseOSCALCatalog(bytes.NewReader(grundschutzCatalogJSON))
	if err != nil {
		return nil, err
	}
	return ExtractControlsFromCatalog(catalog, "Grundschutz++", grundschutzAdditionalMapper), nil
}
