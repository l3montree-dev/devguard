package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm/logger"
)

type Log struct {
	ID               uuid.UUID       `json:"id" gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	OrgID            uuid.UUID       `json:"orgID"`
	ProjectID        uuid.UUID       `json:"projectID"`
	AssetID          uuid.UUID       `json:"assetID"`
	AssetVersionName string          `json:"assetVersionName"`
	CreatedAt        time.Time       `json:"createdAt"`
	LogLevel         logger.LogLevel `json:"logLevel"`
	Message          string          `json:"message"`
}

func (m Log) TableName() string {
	return "logs"
}
