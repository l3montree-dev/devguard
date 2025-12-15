package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
)

type VulnEvent struct {
	Model
	Type                     dtos.VulnEventType               `json:"type" gorm:"type:text"`
	VulnID                   string                           `json:"vulnId"`
	VulnType                 dtos.VulnType                    `json:"dtos.VulnType" gorm:"type:text;not null;default:'dependencyVuln'"`
	UserID                   string                           `json:"userId"`
	Justification            *string                          `json:"justification" gorm:"type:text;"`
	MechanicalJustification  dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	ArbitraryJSONData        string                           `json:"arbitraryJSONData" gorm:"type:text;"`
	arbitraryJSONData        map[string]any
	OriginalAssetVersionName *string            `json:"originalAssetVersionName" gorm:"column:original_asset_version_name;type:text;default:null;"`
	Upstream                 dtos.UpstreamState `json:"upstream" gorm:"default:0;not null;"`
}

type VulnEventDetail struct {
	VulnEvent

	AssetVersionName string `json:"assetVersionName" gorm:"column:asset_version_name"`
	Slug             string `json:"assetVersionSlug" gorm:"column:slug"`
	CVEID            string `json:"cveID" gorm:"column:cve_id"`
	ComponentPurl    string `json:"packageName"`
	URI              string `json:"uri"`
}

func EventTypeToVulnState(eventType dtos.VulnEventType) (dtos.VulnState, error) {
	switch eventType {
	case dtos.EventTypeComment:
		return dtos.VulnStateOpen, nil
	case dtos.EventTypeFixed:
		return dtos.VulnStateFixed, nil
	case dtos.EventTypeDetected:
		fallthrough
	case dtos.EventTypeReopened:
		return dtos.VulnStateOpen, nil
	case dtos.EventTypeAccepted:
		return dtos.VulnStateAccepted, nil
	case dtos.EventTypeFalsePositive:
		return dtos.VulnStateFalsePositive, nil
	case dtos.EventTypeMarkedForTransfer:
		return dtos.VulnStateMarkedForTransfer, nil
	default:
		return "", fmt.Errorf("event type %s does not map to a vuln state", eventType)
	}
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
	if event.Upstream != dtos.UpstreamStateInternal && event.Type == dtos.EventTypeAccepted {
		// its an external accepted event that should not modify state
		return
	}

	switch event.Type {
	case dtos.EventTypeLicenseDecision:
		finalLicenseDecision, ok := (event.GetArbitraryJSONData()["finalLicenseDecision"]).(string)
		if !ok {
			slog.Error("could not parse final license decision", "dependencyVulnID",

				event.VulnID)
			return
		}
		v := vuln.(*LicenseRisk)
		v.SetFinalLicenseDecision(finalLicenseDecision)
		v.SetState(dtos.VulnStateFixed)
	case dtos.EventTypeFixed:
		vuln.SetState(dtos.VulnStateFixed)
	case dtos.EventTypeReopened:
		if event.Upstream == dtos.UpstreamStateExternal {
			return
		}
		vuln.SetState(dtos.VulnStateOpen)
	case dtos.EventTypeDetected:
		// event type detected will always be applied!
		f, ok := (event.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			f = vuln.GetRawRiskAssessment()
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
		vuln.SetState(dtos.VulnStateOpen)
	case dtos.EventTypeAccepted:
		vuln.SetState(dtos.VulnStateAccepted)
	case dtos.EventTypeFalsePositive:
		if event.Upstream == dtos.UpstreamStateExternal {
			return
		}
		vuln.SetState(dtos.VulnStateFalsePositive)
	case dtos.EventTypeMarkedForTransfer:
		vuln.SetState(dtos.VulnStateMarkedForTransfer)
	case dtos.EventTypeRawRiskAssessmentUpdated:
		f, ok := (event.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnID", event.VulnID)
			return
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
	}

}

func NewAcceptedEvent(vulnID string, vulnType dtos.VulnType, userID, justification string, upstream dtos.UpstreamState) VulnEvent {

	return VulnEvent{
		Type:          dtos.EventTypeAccepted,
		VulnID:        vulnID,
		UserID:        userID,
		VulnType:      vulnType,
		Justification: &justification,
		Upstream:      upstream,
	}
}

func NewReopenedEvent(vulnID string, vulnType dtos.VulnType, userID, justification string, upstream dtos.UpstreamState) VulnEvent {
	return VulnEvent{
		Type:          dtos.EventTypeReopened,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
		Upstream:      upstream,
	}
}

func NewCommentEvent(vulnID string, vulnType dtos.VulnType, userID, justification string, upstream dtos.UpstreamState) VulnEvent {
	return VulnEvent{
		Type:          dtos.EventTypeComment,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
		Upstream:      upstream,
	}
}

func NewFalsePositiveEvent(vulnID string, vulnType dtos.VulnType, userID, justification string, mechanicalJustification dtos.MechanicalJustificationType, artifactName string, upstream dtos.UpstreamState) VulnEvent {
	ev := VulnEvent{
		Type:                    dtos.EventTypeFalsePositive,
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

func NewFixedEvent(vulnID string, vulnType dtos.VulnType, userID string, artifactName string, upstream dtos.UpstreamState) VulnEvent {
	ev := VulnEvent{
		Type:     dtos.EventTypeFixed,
		VulnType: vulnType,
		VulnID:   vulnID,
		UserID:   userID,
		Upstream: upstream,
	}
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName})
	return ev
}

func NewLicenseDecisionEvent(vulnID string, vulnType dtos.VulnType, userID string, justification, artifactName string, finalLicenseDecision string) VulnEvent {
	ev := VulnEvent{
		Type:          dtos.EventTypeLicenseDecision,
		VulnType:      vulnType,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName, "finalLicenseDecision": finalLicenseDecision})
	return ev
}

func NewDetectedEvent(vulnID string, vulnType dtos.VulnType, userID string, riskCalculationReport dtos.RiskCalculationReport, scannerID string, upstream dtos.UpstreamState) VulnEvent {
	if upstream == dtos.UpstreamStateExternal {
		// detected events can ONLY be accepted!
		upstream = dtos.UpstreamStateExternalAccepted
	}
	ev := VulnEvent{
		Type:     dtos.EventTypeDetected,
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

func NewMitigateEvent(vulnID string, vulnType dtos.VulnType, userID string, justification string, arbitraryData map[string]any) VulnEvent {
	ev := VulnEvent{
		Type:          dtos.EventTypeMitigate,
		VulnID:        vulnID,
		VulnType:      vulnType,
		UserID:        userID,
		Justification: &justification,
	}
	ev.SetArbitraryJSONData(arbitraryData)
	return ev
}

func NewRawRiskAssessmentUpdatedEvent(vulnID string, vulnType dtos.VulnType, userID string, justification string, oldRisk *float64, report dtos.RiskCalculationReport) VulnEvent {
	event := VulnEvent{
		Type:          dtos.EventTypeRawRiskAssessmentUpdated,
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
