package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/obj"
)

type FlawEventType string

const (
	EventTypeDetected FlawEventType = "detected"
	EventTypeFixed    FlawEventType = "fixed"
	EventTypeReopened FlawEventType = "reopened"

	//EventTypeRiskAssessmentUpdated FlawEventType = "riskAssessmentUpdated"
	EventTypeAccepted          FlawEventType = "accepted"
	EventTypeMitigate          FlawEventType = "mitigate"
	EventTypeFalsePositive     FlawEventType = "falsePositive"
	EventTypeMarkedForTransfer FlawEventType = "markedForTransfer"

	EventTypeRawRiskAssessmentUpdated FlawEventType = "rawRiskAssessmentUpdated"

	EventTypeComment FlawEventType = "comment"
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

func (e FlawEvent) Apply(flaw *DependencyVulnerability) {
	switch e.Type {
	case EventTypeFixed:
		flaw.State = FlawStateFixed
	case EventTypeReopened:
		flaw.State = FlawStateOpen
	case EventTypeDetected:
		flaw.State = FlawStateOpen
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "flawId", e.FlawID)
			return
		}
		flaw.RawRiskAssessment = &f
	case EventTypeAccepted:
		flaw.State = FlawStateAccepted
	case EventTypeFalsePositive:
		flaw.State = FlawStateFalsePositive
	case EventTypeMarkedForTransfer:
		flaw.State = FlawStateMarkedForTransfer
	case EventTypeRawRiskAssessmentUpdated:
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "flawId", e.FlawID)
			return
		}
		flaw.RawRiskAssessment = &f
		flaw.RiskRecalculatedAt = time.Now()
	}
}

func NewAcceptedEvent(flawID, userID, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeAccepted,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewReopenedEvent(flawID, userID, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeReopened,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewCommentEvent(flawID, userID, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeComment,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewFalsePositiveEvent(flawID, userID, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeFalsePositive,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewFixedEvent(flawID string, userID string) FlawEvent {
	return FlawEvent{
		Type:   EventTypeFixed,
		FlawID: flawID,
		UserID: userID,
	}
}

func NewDetectedEvent(flawID string, userID string, riskCalculationReport obj.RiskCalculationReport) FlawEvent {
	ev := FlawEvent{
		Type:   EventTypeDetected,
		FlawID: flawID,
		UserID: userID,
	}

	ev.SetArbitraryJsonData(riskCalculationReport.Map())

	return ev
}

func NewMitigateEvent(flawID string, userID string, justification string, arbitraryData map[string]any) FlawEvent {
	ev := FlawEvent{
		Type:          EventTypeMitigate,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJsonData(arbitraryData)
	return ev
}

func NewRawRiskAssessmentUpdatedEvent(flawID string, userID string, justification string, report obj.RiskCalculationReport) FlawEvent {
	event := FlawEvent{
		Type:          EventTypeRawRiskAssessmentUpdated,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
	event.SetArbitraryJsonData(report.Map())
	return event
}

func CheckStatusType(statusType string) error {
	switch statusType {
	case "fixed":
		return nil
	case "comment":
		return nil
	case "detected":
		return nil
	case "accepted":
		return nil
	case "reopened":
		return nil
	case "mitigate":
		return nil
	case "falsePositive":
		return nil
	case "markedForTransfer":
		return nil
	default:
		return fmt.Errorf("invalid status type")
	}
}
