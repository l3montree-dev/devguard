package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/obj"
)

type VulnEventType string

const (
	EventTypeDetected VulnEventType = "detected"
	EventTypeFixed    VulnEventType = "fixed"
	EventTypeReopened VulnEventType = "reopened"

	//EventTypeRiskAssessmentUpdated VulnEventType = "riskAssessmentUpdated"
	EventTypeAccepted          VulnEventType = "accepted"
	EventTypeMitigate          VulnEventType = "mitigate"
	EventTypeFalsePositive     VulnEventType = "falsePositive"
	EventTypeMarkedForTransfer VulnEventType = "markedForTransfer"

	EventTypeRawRiskAssessmentUpdated VulnEventType = "rawRiskAssessmentUpdated"

	EventTypeComment VulnEventType = "comment"
)

type VulnEvent struct {
	Model
	Type   VulnEventType `json:"type" gorm:"type:text"`
	VulnID string        `json:"vulnId"`
	UserID string        `json:"userId"`

	Justification *string `json:"justification" gorm:"type:text;"`

	ArbitraryJsonData string `json:"arbitraryJsonData" gorm:"type:text;"`
	arbitraryJsonData map[string]any
}

func (e *VulnEvent) GetArbitraryJsonData() map[string]any {
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

func (e *VulnEvent) SetArbitraryJsonData(data map[string]any) {
	e.arbitraryJsonData = data
	// parse the additional data
	dataBytes, err := json.Marshal(e.arbitraryJsonData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "dependencyVulnId", e.ID)
	}
	e.ArbitraryJsonData = string(dataBytes)
}
func (m VulnEvent) TableName() string {
	return "dependencyVuln_events"
}

func (e VulnEvent) Apply(dependencyVuln *DependencyVuln) {
	switch e.Type {
	case EventTypeFixed:
		dependencyVuln.State = VulnStateFixed
	case EventTypeReopened:
		dependencyVuln.State = VulnStateOpen
	case EventTypeDetected:
		dependencyVuln.State = VulnStateOpen
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnId", e.VulnID)
			return
		}
		dependencyVuln.RawRiskAssessment = &f
	case EventTypeAccepted:
		dependencyVuln.State = VulnStateAccepted
	case EventTypeFalsePositive:
		dependencyVuln.State = VulnStateFalsePositive
	case EventTypeMarkedForTransfer:
		dependencyVuln.State = VulnStateMarkedForTransfer
	case EventTypeRawRiskAssessmentUpdated:
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnId", e.VulnID)
			return
		}
		dependencyVuln.RawRiskAssessment = &f
		dependencyVuln.RiskRecalculatedAt = time.Now()
	}
}

func (e VulnEvent) ApplyFirstPartyVulnEvent(firstPartyVuln *FirstPartyVulnerability) {
	switch e.Type {
	case EventTypeFixed:
		firstPartyVuln.State = VulnStateFixed
	case EventTypeReopened:
		firstPartyVuln.State = VulnStateOpen
	case EventTypeDetected:
		firstPartyVuln.State = VulnStateOpen
	case EventTypeAccepted:
		firstPartyVuln.State = VulnStateAccepted
	case EventTypeFalsePositive:
		firstPartyVuln.State = VulnStateFalsePositive
	case EventTypeMarkedForTransfer:
		firstPartyVuln.State = VulnStateMarkedForTransfer
	case EventTypeRawRiskAssessmentUpdated:
	}
}

func NewAcceptedEvent(vulnID, userID, justification string) VulnEvent {

	return VulnEvent{
		Type:          EventTypeAccepted,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewReopenedEvent(vulnID, userID, justification string) VulnEvent {
	return VulnEvent{
		Type:          EventTypeReopened,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewCommentEvent(vulnID, userID, justification string) VulnEvent {
	return VulnEvent{
		Type:          EventTypeComment,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewFalsePositiveEvent(vulnID, userID, justification string) VulnEvent {
	return VulnEvent{
		Type:          EventTypeFalsePositive,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewFixedEvent(vulnID string, userID string) VulnEvent {
	return VulnEvent{
		Type:   EventTypeFixed,
		VulnID: vulnID,
		UserID: userID,
	}
}

func NewDetectedEvent(vulnID string, userID string, riskCalculationReport obj.RiskCalculationReport) VulnEvent {
	ev := VulnEvent{
		Type:   EventTypeDetected,
		VulnID: vulnID,
		UserID: userID,
	}

	ev.SetArbitraryJsonData(riskCalculationReport.Map())

	return ev
}

func NewMitigateEvent(vulnID string, userID string, justification string, arbitraryData map[string]any) VulnEvent {
	ev := VulnEvent{
		Type:          EventTypeMitigate,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJsonData(arbitraryData)
	return ev
}

func NewRawRiskAssessmentUpdatedEvent(vulnID string, userID string, justification string, report obj.RiskCalculationReport) VulnEvent {
	event := VulnEvent{
		Type:          EventTypeRawRiskAssessmentUpdated,
		VulnID:        vulnID,
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
