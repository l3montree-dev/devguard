package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
)

type VulnEventType string

type VulnType string

const (
	VulnTypeDependencyVuln VulnType = "dependencyVuln"
	VulnTypeFirstPartyVuln VulnType = "firstPartyVuln"
)

const (
	// Manual Events (Events that required User Interaction) (see asset_version_service.go @ getDatesForVulnerabilityEvent)
	EventTypeFixed    VulnEventType = "fixed"
	EventTypeReopened VulnEventType = "reopened"

	EventTypeAccepted          VulnEventType = "accepted"
	EventTypeMitigate          VulnEventType = "mitigate"
	EventTypeFalsePositive     VulnEventType = "falsePositive"
	EventTypeMarkedForTransfer VulnEventType = "markedForTransfer"
	EventTypeComment           VulnEventType = "comment"

	// Automated Events (Events that are triggered by automation's on the server)
	EventTypeDetected                VulnEventType = "detected"
	EventTypeDetectedOnAnotherBranch VulnEventType = "detectedOnAnotherBranch"

	// EventTypeRiskAssessmentUpdated VulnEventType = "riskAssessmentUpdated"
	EventTypeRawRiskAssessmentUpdated VulnEventType = "rawRiskAssessmentUpdated"

	EventTypeAddedScanner   VulnEventType = "addedScanner"
	EventTypeRemovedScanner VulnEventType = "removedScanner"
)

type MechanicalJustificationType string

const (
	ComponentNotPresent                         MechanicalJustificationType = "component_not_present"
	VulnerableCodeNotPresent                    MechanicalJustificationType = "vulnerable_code_not_present"
	VulnerableCodeNotInExecutePath              MechanicalJustificationType = "vulnerable_code_not_in_execute_path"
	VulnerableCodeCannotBeControlledByAdversary MechanicalJustificationType = "vulnerable_code_cannot_be_controlled_by_adversary"
	InlineMitigationsAlreadyExist               MechanicalJustificationType = "inline_mitigations_already_exist"
)

type VulnEvent struct {
	Model
	Type                     VulnEventType               `json:"type" gorm:"type:text"`
	VulnID                   string                      `json:"vulnId"`
	VulnType                 VulnType                    `json:"vulnType" gorm:"type:text;not null;default:'dependencyVuln'"`
	UserID                   string                      `json:"userId"`
	Justification            *string                     `json:"justification" gorm:"type:text;"`
	MechanicalJustification  MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	ArbitraryJSONData        string                      `json:"arbitraryJSONData" gorm:"type:text;"`
	arbitraryJSONData        map[string]any
	OriginalAssetVersionName *string `json:"originalAssetVersionName" gorm:"column:original_asset_version_name;type:text;default:null;"`
}

type VulnEventDetail struct {
	VulnEvent

	AssetVersionName string `json:"assetVersionName" gorm:"column:asset_version_name"`
	Slug             string `json:"assetVersionSlug" gorm:"column:slug"`
	CVEID            string `json:"cveID" gorm:"column:cve_id"`
	ComponentPurl    string `json:"packageName"`
	URI              string `json:"uri"`
}

func (e *VulnEvent) GetArbitraryJSONData() map[string]any {
	// parse the additional data
	if e.ArbitraryJSONData == "" {
		return make(map[string]any)
	}
	if e.arbitraryJSONData == nil {
		e.arbitraryJSONData = make(map[string]any)
		err := json.Unmarshal([]byte(e.ArbitraryJSONData), &e.arbitraryJSONData)
		if err != nil {
			slog.Error("could not parse additional data", "err", err, "dependencyVulnID", e.ID)
		}
	}
	return e.arbitraryJSONData
}

func (e *VulnEvent) SetArbitraryJSONData(data map[string]any) {
	e.arbitraryJSONData = data
	// parse the additional data
	dataBytes, err := json.Marshal(e.arbitraryJSONData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "dependencyVulnID", e.ID)
	}
	e.ArbitraryJSONData = string(dataBytes)
}
func (m VulnEvent) TableName() string {
	return "vuln_events"
}

func (e VulnEvent) Apply(vuln Vuln) {
	switch e.Type {
	case EventTypeDetectedOnAnotherBranch:
		// do nothing
		return
	case EventTypeAddedScanner:
		scannerID, ok := (e.GetArbitraryJSONData()["scannerIDs"]).(string)
		if !ok {
			slog.Error("could not parse scanner id", "dependencyVulnID", e.VulnID)
			return
		}
		vuln.AddScannerID(scannerID)
	case EventTypeRemovedScanner:
		scannerID, ok := (e.GetArbitraryJSONData()["scannerIDs"]).(string)
		if !ok {
			slog.Error("could not parse scanner id", "dependencyVulnID", e.VulnID)
			return
		}
		vuln.RemoveScannerID(scannerID)
	case EventTypeFixed:
		vuln.SetState(VulnStateFixed)
	case EventTypeReopened:
		vuln.SetState(VulnStateOpen)
	case EventTypeDetected:
		vuln.SetState(VulnStateOpen)
		f, ok := (e.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnID", e.VulnID)
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
		f, ok := (e.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnID", e.VulnID)
			return
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
	}
}

func NewAcceptedEvent(vulnID string, vulnType VulnType, userID, justification string) VulnEvent {

	return VulnEvent{
		Type:          EventTypeAccepted,
		VulnID:        vulnID,
		UserID:        userID,
		VulnType:      vulnType,
		Justification: &justification,
	}
}

func NewReopenedEvent(vulnID string, vulnType VulnType, userID, justification string) VulnEvent {
	return VulnEvent{
		Type:          EventTypeReopened,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewCommentEvent(vulnID string, vulnType VulnType, userID, justification string) VulnEvent {
	return VulnEvent{
		Type:          EventTypeComment,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewFalsePositiveEvent(vulnID string, vulnType VulnType, userID, justification string, mechanicalJustification MechanicalJustificationType, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:                    EventTypeFalsePositive,
		VulnID:                  vulnID,
		VulnType:                vulnType,
		UserID:                  userID,
		Justification:           &justification,
		MechanicalJustification: mechanicalJustification,
	}
	ev.SetArbitraryJSONData(map[string]any{"scannerIDs": scannerID})
	return ev
}

func NewFixedEvent(vulnID string, vulnType VulnType, userID string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeFixed,
		VulnType: vulnType,
		VulnID:   vulnID,
		UserID:   userID,
	}
	ev.SetArbitraryJSONData(map[string]any{"scannerIDs": scannerID})
	return ev
}

func NewDetectedEvent(vulnID string, vulnType VulnType, userID string, riskCalculationReport common.RiskCalculationReport, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeDetected,
		VulnType: vulnType,
		VulnID:   vulnID,
		UserID:   userID,
	}

	m := riskCalculationReport.Map()
	m["scannerIDs"] = scannerID

	ev.SetArbitraryJSONData(m)

	return ev
}

func NewDetectedOnAnotherBranchEvent(vulnID string, vulnType VulnType, userID string, riskCalculationReport common.RiskCalculationReport, scannerID string, assetVersionName string) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeDetectedOnAnotherBranch,
		VulnType: vulnType,
		VulnID:   vulnID,
		UserID:   userID,
	}

	m := riskCalculationReport.Map()
	m["scannerIDs"] = scannerID
	m["assetVersionName"] = assetVersionName

	ev.SetArbitraryJSONData(m)

	return ev
}

func NewMitigateEvent(vulnID string, vulnType VulnType, userID string, justification string, arbitraryData map[string]any) VulnEvent {
	ev := VulnEvent{
		Type:          EventTypeMitigate,
		VulnID:        vulnID,
		VulnType:      vulnType,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJSONData(arbitraryData)
	return ev
}

func NewRawRiskAssessmentUpdatedEvent(vulnID string, vulnType VulnType, userID string, justification string, oldRisk *float64, report common.RiskCalculationReport) VulnEvent {
	event := VulnEvent{
		Type:          EventTypeRawRiskAssessmentUpdated,
		VulnID:        vulnID,
		VulnType:      vulnType,
		UserID:        userID,
		Justification: &justification,
	}
	m := report.Map()
	if oldRisk != nil {
		m["oldRisk"] = *oldRisk
	}

	event.SetArbitraryJSONData(m)
	return event
}

func NewAddedScannerEvent(vulnID string, vulnType VulnType, userID string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeAddedScanner,
		VulnID:   vulnID,
		VulnType: vulnType,
		UserID:   userID,
	}

	ev.SetArbitraryJSONData(map[string]any{"scannerIDs": scannerID})
	return ev
}

func NewRemovedScannerEvent(vulnID string, vulnType VulnType, userID string, scannerID string) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeRemovedScanner,
		VulnID:   vulnID,
		VulnType: vulnType,
		UserID:   userID,
	}

	ev.SetArbitraryJSONData(map[string]any{"scannerIDs": scannerID})
	return ev
}

func (ev VulnEvent) IsScanUnreleatedEvent() bool {
	switch ev.Type {
	case EventTypeAddedScanner, EventTypeRemovedScanner, EventTypeDetectedOnAnotherBranch, EventTypeRawRiskAssessmentUpdated:
		return false
	default:
		return true
	}
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
