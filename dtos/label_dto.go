package dtos

import (
	"time"

	"github.com/google/uuid"
)

type Label struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  *uuid.UUID `json:"organization_id"`
	ProjectID       *uuid.UUID `json:"project_id"`
	AssetID         *uuid.UUID `json:"asset_id"`
	Label           string     `json:"label" gorm:"label"`
	BackgroundColor string     `json:"background_color"`
	CreatedAt       time.Time  `json:"created_at"`
	TextColor       string     `json:"text_color"`
}
