package models

import (
	"gorm.io/datatypes"
)

type FlawEventType string

const (
	EventTypeDetected FlawEventType = "detected"
	EventTypeFixed    FlawEventType = "fixed"

	//EventTypeRiskAssessmentUpdated FlawEventType = "riskAssessmentUpdated"
	EventTypeMarkedForMitigation FlawEventType = "markedForMitigation"
	EventTypeFalsePositive       FlawEventType = "falsePositive"
	EventTypeMarkedForTransfer   FlawEventType = "markedForTransfer"
	EventTypeMarkedForAvoidance  FlawEventType = "markedForAvoidance"
	EventTypeAvoid               FlawEventType = "avoid"
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
		flaw.State = FlawStateFixed
	case EventTypeDetected:
		flaw.State = FlawStateOpen
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
