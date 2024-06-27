package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
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

	ArbitraryJsonData string `json:"arbitraryJsonData" gorm:"type:text;"`
	arbitraryJsonData map[string]any
}

func (e *FlawEvent) GetArbitraryJsonData() map[string]any {
	// parse the additional data
	if e.ArbitraryJsonData == "" {
		return make(map[string]any)
	}
	if e.arbitraryJsonData == nil {
		e.arbitraryJsonData = make(map[string]any)
		err := json.Unmarshal([]byte(e.ArbitraryJsonData), &e.arbitraryJsonData)
		if err != nil {
			slog.Error("could not parse additional data", "err", err, "flawId", e.ID)
		}
	}
	return e.arbitraryJsonData
}

func (e *FlawEvent) SetArbitraryJsonData(data map[string]any) {
	e.arbitraryJsonData = data
	// parse the additional data
	dataBytes, err := json.Marshal(e.arbitraryJsonData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "flawId", e.ID)
	}
	e.ArbitraryJsonData = string(dataBytes)
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
		f, ok := (e.GetArbitraryJsonData()["newRiskAssessment"]).(float64)
		if !ok {
			slog.Error("could not parse newRiskAssessment", "flawId", e.FlawID)
			return
		}
		flaw.RawRiskAssessment = &f

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

func NewRawRiskAssessmentUpdatedEvent(flawID string, userID string, justification string, oldRiskAssessment float64, newRiskAssessment float64) FlawEvent {
	event := FlawEvent{
		Type:          EventTypeRawRiskAssessmentUpdated,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
	event.SetArbitraryJsonData(map[string]any{
		"oldRiskAssessment": oldRiskAssessment,
		"newRiskAssessment": newRiskAssessment,
	})
	return event
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
