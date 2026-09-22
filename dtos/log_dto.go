package dtos

import (
	"time"

	"github.com/google/uuid"
)

type LogLevel string

const (
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

type LogDTO struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	OrgID       *uuid.UUID `json:"orgID"`
	ProjectID   *uuid.UUID `json:"projectID"`
	AssetID     *uuid.UUID `json:"assetID"`
	LogLevel    LogLevel   `json:"logLevel"`
	Message     string     `json:"message"`
	ProjectName *string    `json:"projectName,omitempty"`
	AssetName   *string    `json:"assetName,omitempty"`
	OrgName     *string    `json:"orgName,omitempty"`
}
