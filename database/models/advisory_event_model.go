package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

type AdvisoryEvent struct {
	ID           uuid.UUID              `json:"id" gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	CreatedAt    time.Time              `json:"createdAt"`
	Type         dtos.AdvisoryEventType `json:"type" gorm:"type:text"`
	UserID       string                 `json:"userId"`
	AdvisoryID   uuid.UUID              `json:"advisoryId"`
	Title        *string                `json:"title" gorm:"type:text"`
	Description  *string                `json:"description" gorm:"type:text"`
	Severity     *string                `json:"severity" gorm:"type:text"`
	VectorString *string                `json:"vectorString" gorm:"type:text"`
	State        *string                `json:"state" gorm:"type:text"`
}

func (AdvisoryEvent) TableName() string {
	return "advisories_events"
}
