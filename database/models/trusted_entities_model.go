package models

import (
	"time"

	"github.com/google/uuid"
)

type TrustedEntity struct {
	TrustedEntityID uuid.UUID  `json:"trusted_entity_id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	OrganizationID  *uuid.UUID `json:"organization_id" gorm:"type:uuid;default:null;uniqueIndex:idx_trusted_entities_unique"`
	ProjectID       *uuid.UUID `json:"project_id" gorm:"type:uuid;default:null;uniqueIndex:idx_trusted_entities_unique"`
	EntityType      string     `json:"entity_type" gorm:"not null;type:text"`
	Trustscore      float64    `json:"trustscore" gorm:"not null;default:0"`
	CreatedAt       time.Time  `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt       time.Time  `json:"updatedAt" gorm:"autoUpdateTime"`
}

func (m TrustedEntity) TableName() string {
	return "trusted_entities"
}
