package models

import (
	"fmt"
)

type FlawEventType string

const (
	EventTypeDetected FlawEventType = "detected"
	EventTypeFixed    FlawEventType = "fixed"

	//EventTypeRiskAssessmentUpdated FlawEventType = "riskAssessmentUpdated"
	EventTypeAccepted            FlawEventType = "accepted"
	EventTypeMarkedForMitigation FlawEventType = "markedForMitigation"
	EventTypeFalsePositive       FlawEventType = "falsePositive"
	EventTypeMarkedForTransfer   FlawEventType = "markedForTransfer"

	EventTypeRawRiskAssessmentUpdated FlawEventType = "rawRiskAssessmentUpdated"
)

type FlawEvent struct {
	Model
	Type   FlawEventType `json:"type" gorm:"type:text"`
	FlawID string        `json:"flawId"`
	UserID string        `json:"userId"`

	Justification *string `json:"justification" gorm:"type:text;"`
}

func (m FlawEvent) TableName() string {
	return "flaw_events"
}

func (e FlawEvent) Apply(flaw *Flaw) {
	switch e.Type {
	case EventTypeFixed:
		flaw.State = FlawStateFixed
	case EventTypeDetected:
		flaw.State = FlawStateOpen
	case EventTypeAccepted:
		flaw.State = FlawStateAccepted
	case EventTypeMarkedForMitigation:
		flaw.State = FlawStateMarkedForMitigation
	case EventTypeFalsePositive:
		flaw.State = FlawStateFalsePositive
	case EventTypeMarkedForTransfer:
		flaw.State = FlawStateMarkedForTransfer
	case EventTypeRawRiskAssessmentUpdated:
		//do nothing

	}

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

func CheckStatusType(statusType string) error {
	switch statusType {
	case "fixed":
		return nil
	case "detected":
		return nil
	case "accepted":
		return nil
	case "markedForMitigation":
		return nil
	case "falsePositive":
		return nil
	case "markedForTransfer":
		return nil
	default:
		return fmt.Errorf("invalid status type")
	}
}
