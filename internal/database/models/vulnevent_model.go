package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
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

	EventTypeAddedScanner   VulnEventType = "addedScanner"
	EventTypeRemovedScanner VulnEventType = "removedScanner"
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

type VulnEventDetail struct {
	VulnEvent

	AssetVersionName string `json:"assetVersionName" gorm:"column:asset_version_name"`
	Slug             string `json:"assetVersionSlug" gorm:"column:slug"`
	CVEID            string `json:"cveId" gorm:"column:cve_id"`
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
	return "vuln_events"
}

func (e VulnEvent) Apply(vuln Vuln) {
	switch e.Type {
	case EventTypeAddedScanner:
		scannerID, ok := (e.GetArbitraryJsonData()["scannerIds"]).(string)
		if !ok {
			slog.Error("could not parse scanner id", "dependencyVulnId", e.VulnID)
			return
		}
		vuln.AddScannerID(scannerID)
	case EventTypeRemovedScanner:
		scannerID, ok := (e.GetArbitraryJsonData()["scannerIds"]).(string)
		if !ok {
			slog.Error("could not parse scanner id", "dependencyVulnId", e.VulnID)
			return
		}
		vuln.RemoveScannerID(scannerID)
	case EventTypeFixed:
		vuln.SetState(VulnStateFixed)
	case EventTypeReopened:
		vuln.SetState(VulnStateOpen)
	case EventTypeDetected:
		vuln.SetState(VulnStateOpen)
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnId", e.VulnID)
			return
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
	case EventTypeAccepted:
		vuln.SetState(VulnStateAccepted)
	case EventTypeFalsePositive:
		vuln.SetState(VulnStateFalsePositive)
	case EventTypeMarkedForTransfer:
		vuln.SetState(VulnStateMarkedForTransfer)
	case EventTypeRawRiskAssessmentUpdated:
		f, ok := (e.GetArbitraryJsonData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnId", e.VulnID)
			return
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
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

func NewFalsePositiveEvent(vulnID, userID, justification string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:          EventTypeFalsePositive,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJsonData(map[string]any{"scannerIds": scannerID})
	return ev
}

func NewFixedEvent(vulnID string, userID string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:   EventTypeFixed,
		VulnID: vulnID,
		UserID: userID,
	}
	ev.SetArbitraryJsonData(map[string]any{"scannerIds": scannerID})
	return ev
}

func NewDetectedEvent(vulnID string, userID string, riskCalculationReport common.RiskCalculationReport, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:   EventTypeDetected,
		VulnID: vulnID,
		UserID: userID,
	}

	m := riskCalculationReport.Map()
	m["scannerIds"] = scannerID

	ev.SetArbitraryJsonData(m)

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

func NewRawRiskAssessmentUpdatedEvent(vulnID string, userID string, justification string, oldRisk *float64, report common.RiskCalculationReport) VulnEvent {
	event := VulnEvent{
		Type:          EventTypeRawRiskAssessmentUpdated,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
	m := report.Map()
	if oldRisk != nil {
		m["oldRisk"] = *oldRisk
	}

	event.SetArbitraryJsonData(m)
	return event
}

func NewAddedScannerEvent(vulnID string, userID string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:   EventTypeAddedScanner,
		VulnID: vulnID,
		UserID: userID,
	}

	ev.SetArbitraryJsonData(map[string]any{"scannerIds": scannerID})
	return ev
}

func NewRemovedScannerEvent(vulnID string, userID string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:   EventTypeRemovedScanner,
		VulnID: vulnID,
		UserID: userID,
	}

	ev.SetArbitraryJsonData(map[string]any{"scannerIds": scannerID})
	return ev
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
	case "addedScanner":
		return nil
	case "removedScanner":
		return nil
	default:
		return fmt.Errorf("invalid status type")
	}
}
