package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func LabelToDTO(label models.Label, textColor string) dtos.Label {
	return dtos.Label{
		ID:              label.ID,
		OrganizationID:  label.OrganizationID,
		ProjectID:       label.ProjectID,
		AssetID:         label.AssetID,
		Label:           label.Label,
		BackgroundColor: label.BackgroundColor,
		CreatedAt:       label.CreatedAt,
		TextColor:       textColor,
	}
}
