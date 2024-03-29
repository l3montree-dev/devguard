package models

import (
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type FlawEventType string

const (
	EventTypeDetected FlawEventType = "detected"
	EventTypeFixed    FlawEventType = "fixed"

	EventTypeRiskAssessmentUpdated FlawEventType = "riskAssessmentUpdated"
)

type FlawEvent struct {
	Model
	Type   FlawEventType `json:"type" gorm:"type:text"`
	FlawID uuid.UUID     `json:"flawId"`
	UserID uuid.UUID     `json:"userId"`

	Payload *datatypes.JSON `json:"payload" gorm:"type:jsonb"`
}

func (m FlawEvent) TableName() string {
	return "flaw_events"
}

func (e FlawEvent) Apply(flaw Flaw) Flaw {
	switch e.Type {
	case EventTypeFixed:
		flaw.State = StateFixed
	case EventTypeDetected:
		flaw.State = StateOpen
	}

	return flaw
}
