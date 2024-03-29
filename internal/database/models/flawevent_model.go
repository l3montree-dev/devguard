package models

import (
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
	FlawID string        `json:"flawId"`
	UserID string        `json:"userId"`

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

func NewFixedEvent(flawID string, userID string) FlawEvent {
	return FlawEvent{
		Type:   EventTypeFixed,
		FlawID: flawID,
		UserID: userID,
	}
}

func NewDetectedEvent(flawID string, userID string) FlawEvent {
	return FlawEvent{
		Type:   EventTypeDetected,
		FlawID: flawID,
		UserID: userID,
	}
}
