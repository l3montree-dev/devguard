package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"gorm.io/datatypes"
)

type Type string

const (
	EventTypeDetected Type = "detected"
	EventTypeFixed    Type = "fixed"

	EventTypeRiskAssessmentUpdated Type = "riskAssessmentUpdated"
)

type EventModel struct {
	core.Model
	Type   Type      `json:"type" gorm:"type:text"`
	FlawID uuid.UUID `json:"flawId"`
	UserID uuid.UUID `json:"userId"`

	Payload *datatypes.JSON `json:"payload" gorm:"type:jsonb"`
}

func (m EventModel) TableName() string {
	return "flaw_events"
}

func (e EventModel) Apply(flaw Model) Model {
	switch e.Type {
	case EventTypeFixed:
		flaw.State = StateFixed
	case EventTypeDetected:
		flaw.State = StateOpen
	}

	return flaw
}
