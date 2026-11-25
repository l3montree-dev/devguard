package dtos

import (
	"time"

	"github.com/google/uuid"
)

type LabelRequest struct {
	Label           string `json:"label" validate:"required,max=256"`
	BackgroundColor string `json:"background_color" validate:"required,hexcolor,len=7"`
}

type AttachLabelRequest struct {
	Labels []string `json:"label" validate:"required"`
}

type Label struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  *uuid.UUID `json:"organizationID"`
	ProjectID       *uuid.UUID `json:"projectID"`
	AssetID         *uuid.UUID `json:"assetID"`
	Label           string     `json:"label" gorm:"label"`
	BackgroundColor string     `json:"backgroundColor"`
	CreatedAt       time.Time  `json:"createdAt"`
	TextColor       string     `json:"textColor"`
}
