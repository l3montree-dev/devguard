package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/obj"
)

type DependencyVulnEventType string

const (
	EventTypeDetected DependencyVulnEventType = "detected"
	EventTypeFixed    DependencyVulnEventType = "fixed"
	EventTypeReopened DependencyVulnEventType = "reopened"

	//EventTypeRiskAssessmentUpdated DependencyVulnEventType = "riskAssessmentUpdated"
	EventTypeAccepted          DependencyVulnEventType = "accepted"
	EventTypeMitigate          DependencyVulnEventType = "mitigate"
	EventTypeFalsePositive     DependencyVulnEventType = "falsePositive"
	EventTypeMarkedForTransfer DependencyVulnEventType = "markedForTransfer"

	EventTypeRawRiskAssessmentUpdated DependencyVulnEventType = "rawRiskAssessmentUpdated"

	EventTypeComment DependencyVulnEventType = "comment"
)

type DependencyVulnEvent struct {
	Model
	Type             DependencyVulnEventType `json:"type" gorm:"type:text"`
	DependencyVulnID string                  `json:"dependencyVulnId"`
	UserID           string                  `json:"userId"`

	Justification *string `json:"justification" gorm:"type:text;"`

	ArbitraryJsonData string `json:"arbitraryJsonData" gorm:"type:text;"`
	arbitraryJsonData map[string]any
}

func (e *DependencyVulnEvent) GetArbitraryJsonData() map[string]any {
	// parse the additional data
	if e.ArbitraryJsonData == "" {
		return make(map[string]any)
	}
	if e.arbitraryJsonData == nil {
		e.arbitraryJsonData = make(map[string]any)
		err := json.Unmarshal([]byte(e.ArbitraryJsonData), &e.arbitraryJsonData)
		if err != nil {
			slog.Error("could not parse additional data", "err", err, "dependencyVulnId", e.ID)
		}
	}
	return e.arbitraryJsonData
}

func (e *DependencyVulnEvent) SetArbitraryJsonData(data map[string]any) {
	e.arbitraryJsonData = data
	// parse the additional data
	dataBytes, err := json.Marshal(e.arbitraryJsonData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "dependencyVulnId", e.ID)
	}
	e.ArbitraryJsonData = string(dataBytes)
}
func (m DependencyVulnEvent) TableName() string {
	return "dependencyVuln_events"
}

func (e DependencyVulnEvent) Apply(dependencyVuln *DependencyVulnerability) {
	switch e.Type {
	case EventTypeFixed:
		dependencyVuln.State = DependencyVulnStateFixed
	case EventTypeReopened:
		dependencyVuln.State = DependencyVulnStateOpen
	case EventTypeDetected:
		dependencyVuln.State = DependencyVulnStateOpen
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnId", e.DependencyVulnID)
			return
		}
		dependencyVuln.RawRiskAssessment = &f
	case EventTypeAccepted:
		dependencyVuln.State = DependencyVulnStateAccepted
	case EventTypeFalsePositive:
		dependencyVuln.State = DependencyVulnStateFalsePositive
	case EventTypeMarkedForTransfer:
		dependencyVuln.State = DependencyVulnStateMarkedForTransfer
	case EventTypeRawRiskAssessmentUpdated:
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnId", e.DependencyVulnID)
			return
		}
		dependencyVuln.RawRiskAssessment = &f
		dependencyVuln.RiskRecalculatedAt = time.Now()
	}
}

func NewAcceptedEvent(dependencyVulnID, userID, justification string) DependencyVulnEvent {
	return DependencyVulnEvent{
		Type:             EventTypeAccepted,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
		Justification:    &justification,
	}
}

func NewReopenedEvent(dependencyVulnID, userID, justification string) DependencyVulnEvent {
	return DependencyVulnEvent{
		Type:             EventTypeReopened,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
		Justification:    &justification,
	}
}

func NewCommentEvent(dependencyVulnID, userID, justification string) DependencyVulnEvent {
	return DependencyVulnEvent{
		Type:             EventTypeComment,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
		Justification:    &justification,
	}
}

func NewFalsePositiveEvent(dependencyVulnID, userID, justification string) DependencyVulnEvent {
	return DependencyVulnEvent{
		Type:             EventTypeFalsePositive,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
		Justification:    &justification,
	}
}

func NewFixedEvent(dependencyVulnID string, userID string) DependencyVulnEvent {
	return DependencyVulnEvent{
		Type:             EventTypeFixed,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
	}
}

func NewDetectedEvent(dependencyVulnID string, userID string, riskCalculationReport obj.RiskCalculationReport) DependencyVulnEvent {
	ev := DependencyVulnEvent{
		Type:             EventTypeDetected,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
	}

	ev.SetArbitraryJsonData(riskCalculationReport.Map())

	return ev
}

func NewMitigateEvent(dependencyVulnID string, userID string, justification string, arbitraryData map[string]any) DependencyVulnEvent {
	ev := DependencyVulnEvent{
		Type:             EventTypeMitigate,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
		Justification:    &justification,
	}
	ev.SetArbitraryJsonData(arbitraryData)
	return ev
}

func NewRawRiskAssessmentUpdatedEvent(dependencyVulnID string, userID string, justification string, report obj.RiskCalculationReport) DependencyVulnEvent {
	event := DependencyVulnEvent{
		Type:             EventTypeRawRiskAssessmentUpdated,
		DependencyVulnID: dependencyVulnID,
		UserID:           userID,
		Justification:    &justification,
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
