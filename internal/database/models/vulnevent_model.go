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
	VulnTypeLicenseRisk    VulnType = "licenseRisk"
)

const (
	// Manual Events (Events that required User Interaction) (see asset_version_service.go @ getDatesForVulnerabilityEvent)
	EventTypeFixed           VulnEventType = "fixed"
	EventTypeLicenseDecision VulnEventType = "licenseDecision"
	EventTypeReopened        VulnEventType = "reopened"

	EventTypeAccepted          VulnEventType = "accepted"
	EventTypeMitigate          VulnEventType = "mitigate"
	EventTypeFalsePositive     VulnEventType = "falsePositive"
	EventTypeMarkedForTransfer VulnEventType = "markedForTransfer"
	EventTypeComment           VulnEventType = "comment"

	// Automated Events (Events that are triggered by automation's on the server)
	EventTypeDetected VulnEventType = "detected"

	// EventTypeRiskAssessmentUpdated VulnEventType = "riskAssessmentUpdated"
	EventTypeRawRiskAssessmentUpdated VulnEventType = "rawRiskAssessmentUpdated"
)

type MechanicalJustificationType string

const (
	ComponentNotPresent                         MechanicalJustificationType = "component_not_present"
	VulnerableCodeNotPresent                    MechanicalJustificationType = "vulnerable_code_not_present"
	VulnerableCodeNotInExecutePath              MechanicalJustificationType = "vulnerable_code_not_in_execute_path"
	VulnerableCodeCannotBeControlledByAdversary MechanicalJustificationType = "vulnerable_code_cannot_be_controlled_by_adversary"
	InlineMitigationsAlreadyExist               MechanicalJustificationType = "inline_mitigations_already_exist"
)

type UpstreamState int

const (
	UpstreamStateInternal         UpstreamState = 0
	UpstreamStateExternalAccepted UpstreamState = 1
	UpstreamStateExternal         UpstreamState = 2
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
	OriginalAssetVersionName *string       `json:"originalAssetVersionName" gorm:"column:original_asset_version_name;type:text;default:null;"`
	Upstream                 UpstreamState `json:"upstream" gorm:"default:0;not null;"`
}

type VulnEventDetail struct {
	VulnEvent

	AssetVersionName string `json:"assetVersionName" gorm:"column:asset_version_name"`
	Slug             string `json:"assetVersionSlug" gorm:"column:slug"`
	CVEID            string `json:"cveID" gorm:"column:cve_id"`
	ComponentPurl    string `json:"packageName"`
	URI              string `json:"uri"`
}

func (event *VulnEvent) GetArbitraryJSONData() map[string]any {
	// parse the additional data
	if event.ArbitraryJSONData == "" {
		return make(map[string]any)
	}
	if event.arbitraryJSONData == nil {
		event.arbitraryJSONData = make(map[string]any)
		err := json.Unmarshal([]byte(event.ArbitraryJSONData), &event.arbitraryJSONData)
		if err != nil {
			slog.Error("could not parse additional data", "err", err, "dependencyVulnID", event.ID)
		}
	}
	return event.arbitraryJSONData
}

func (event *VulnEvent) SetArbitraryJSONData(data map[string]any) {
	event.arbitraryJSONData = data
	// parse the additional data
	dataBytes, err := json.Marshal(event.arbitraryJSONData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "dependencyVulnID", event.ID)
	}
	event.ArbitraryJSONData = string(dataBytes)
}
func (event VulnEvent) TableName() string {
	return "vuln_events"
}

func (event VulnEvent) Apply(vuln Vuln) {
	if event.Upstream == UpstreamStateExternal {
		// external event that should not modify state
		return
	}
	if event.Upstream == UpstreamStateExternalAccepted && event.Type == EventTypeAccepted {
		// its an external accepted event that should not modify state
		return
	}
	switch event.Type {
	case EventTypeLicenseDecision:
		finalLicenseDecision, ok := (event.GetArbitraryJSONData()["finalLicenseDecision"]).(string)
		if !ok {
			slog.Error("could not parse final license decision", "dependencyVulnID",

				event.VulnID)
			return
		}
		v := vuln.(*LicenseRisk)
		v.SetFinalLicenseDecision(finalLicenseDecision)
		v.SetState(VulnStateFixed)
	case EventTypeFixed:
		vuln.SetState(VulnStateFixed)
	case EventTypeReopened:
		vuln.SetState(VulnStateOpen)
	case EventTypeDetected:
		vuln.SetState(VulnStateOpen)
		f, ok := (event.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnID", event.VulnID)
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
		f, ok := (event.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnID", event.VulnID)
			return
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
	}

}

func NewAcceptedEvent(vulnID string, vulnType VulnType, userID, justification string, upstream UpstreamState) VulnEvent {

	return VulnEvent{
		Type:          EventTypeAccepted,
		VulnID:        vulnID,
		UserID:        userID,
		VulnType:      vulnType,
		Justification: &justification,
		Upstream:      upstream,
	}
}

func NewReopenedEvent(vulnID string, vulnType VulnType, userID, justification string, upstream UpstreamState) VulnEvent {
	return VulnEvent{
		Type:          EventTypeReopened,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
		Upstream:      upstream,
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

func NewFalsePositiveEvent(vulnID string, vulnType VulnType, userID, justification string, mechanicalJustification MechanicalJustificationType, artifactName string, upstream UpstreamState) VulnEvent {
	ev := VulnEvent{
		Type:                    EventTypeFalsePositive,
		VulnID:                  vulnID,
		VulnType:                vulnType,
		UserID:                  userID,
		Justification:           &justification,
		MechanicalJustification: mechanicalJustification,
		Upstream:                upstream,
	}
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName})
	return ev
}

func NewFixedEvent(vulnID string, vulnType VulnType, userID string, artifactName string, upstream UpstreamState) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeFixed,
		VulnType: vulnType,
		VulnID:   vulnID,
		UserID:   userID,
		Upstream: upstream,
	}
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName})
	return ev
}

func NewLicenseDecisionEvent(vulnID string, vulnType VulnType, userID string, justification, artifactName string, finalLicenseDecision string) VulnEvent {
	ev := VulnEvent{
		Type:          EventTypeLicenseDecision,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName, "finalLicenseDecision": finalLicenseDecision})
	return ev
}

func NewDetectedEvent(vulnID string, vulnType VulnType, userID string, riskCalculationReport common.RiskCalculationReport, scannerID string, upstream UpstreamState) VulnEvent {
	ev := VulnEvent{
		Type:     EventTypeDetected,
		VulnType: vulnType,
		VulnID:   vulnID,
		UserID:   userID,
		Upstream: upstream,
	}

	m := riskCalculationReport.Map()
	m["scannerID"] = scannerID

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
