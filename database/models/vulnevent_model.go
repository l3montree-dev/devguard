package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

type VulnEvent struct {
	ID                       uuid.UUID                        `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt                time.Time                        `json:"createdAt"`
	Type                     dtos.VulnEventType               `json:"type" gorm:"type:text"`
	DependencyVulnID         *uuid.UUID                       `json:"dependencyVulnId" gorm:"type:uuid;column:dependency_vuln_id"`
	LicenseRiskID            *uuid.UUID                       `json:"licenseRiskId" gorm:"type:uuid;column:license_risk_id"`
	FirstPartyVulnID         *uuid.UUID                       `json:"firstPartyVulnId" gorm:"type:uuid;column:first_party_vuln_id"`
	UserID                   string                           `json:"userId"`
	Justification            *string                          `json:"justification" gorm:"type:text;"`
	MechanicalJustification  dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	ArbitraryJSONData        string                           `json:"arbitraryJSONData" gorm:"type:text;"`
	arbitraryJSONData        map[string]any
	OriginalAssetVersionName *string `json:"originalAssetVersionName" gorm:"column:original_asset_version_name;type:text;default:null;"`
	CreatedByVexRule         bool    `json:"createdByVexRule" gorm:"column:created_by_vex_rule;default:false;not null"`
	UserAgent                *string `json:"userAgent" gorm:"column:user_agent;type:text;default:null;"`
}

// GetVulnID returns the non-nil vuln ID from whichever column is set.
func (event VulnEvent) GetVulnID() uuid.UUID {
	if event.DependencyVulnID != nil {
		return *event.DependencyVulnID
	}
	if event.LicenseRiskID != nil {
		return *event.LicenseRiskID
	}
	if event.FirstPartyVulnID != nil {
		return *event.FirstPartyVulnID
	}
	return uuid.Nil
}

// GetVulnType returns the vuln type based on which ID column is set.
func (event VulnEvent) GetVulnType() dtos.VulnType {
	if event.DependencyVulnID != nil {
		return dtos.VulnTypeDependencyVuln
	}
	if event.LicenseRiskID != nil {
		return dtos.VulnTypeLicenseRisk
	}
	if event.FirstPartyVulnID != nil {
		return dtos.VulnTypeFirstPartyVuln
	}
	return ""
}

// SetVulnIDOnEvent sets the appropriate column based on vulnType.
func SetVulnIDOnEvent(event *VulnEvent, vulnID uuid.UUID, vulnType dtos.VulnType) {
	switch vulnType {
	case dtos.VulnTypeDependencyVuln:
		event.DependencyVulnID = &vulnID
	case dtos.VulnTypeLicenseRisk:
		event.LicenseRiskID = &vulnID
	case dtos.VulnTypeFirstPartyVuln:
		event.FirstPartyVulnID = &vulnID
	}
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
			slog.Error("could not parse additional data", "err", err, "vulnEventID", event.ID)
		}
	}
	return event.arbitraryJSONData
}

func (event *VulnEvent) SetArbitraryJSONData(data map[string]any) {
	event.arbitraryJSONData = data
	// parse the additional data
	dataBytes, err := json.Marshal(event.arbitraryJSONData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "vulnEventID", event.ID)
	}
	event.ArbitraryJSONData = string(dataBytes)
}
func (event VulnEvent) TableName() string {
	return "vuln_events"
}

func NewAcceptedEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID, justification string, createdByRule bool, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:             dtos.EventTypeAccepted,
		UserID:           userID,
		Justification:    &justification,
		CreatedByVexRule: createdByRule,
		UserAgent:        &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	return ev
}

func NewReopenedEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID, justification string, createdByRule bool, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:             dtos.EventTypeReopened,
		UserID:           userID,
		Justification:    &justification,
		CreatedByVexRule: createdByRule,
		UserAgent:        &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	return ev
}

func NewCommentEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID, justification string, createdByRule bool, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:             dtos.EventTypeComment,
		UserID:           userID,
		Justification:    &justification,
		CreatedByVexRule: createdByRule,
		UserAgent:        &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	return ev
}

func NewFalsePositiveEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID, justification string, mechanicalJustification dtos.MechanicalJustificationType, artifactName string, createdByRule bool, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:                    dtos.EventTypeFalsePositive,
		UserID:                  userID,
		Justification:           &justification,
		MechanicalJustification: mechanicalJustification,
		CreatedByVexRule:        createdByRule,
		UserAgent:               &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName})
	return ev
}

func NewFixedEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID string, artifactName string, createdByRule bool, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:             dtos.EventTypeFixed,
		UserID:           userID,
		CreatedByVexRule: createdByRule,
		UserAgent:        &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName})
	return ev
}

func NewLicenseDecisionEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID string, justification, artifactName string, finalLicenseDecision string, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:          dtos.EventTypeLicenseDecision,
		UserID:        userID,
		Justification: &justification,
		UserAgent:     &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	ev.SetArbitraryJSONData(map[string]any{"artifactNames": artifactName, "finalLicenseDecision": finalLicenseDecision})
	return ev
}

func NewDetectedEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID string, riskCalculationReport dtos.RiskCalculationReport, scannerID string, createdByRule bool, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:             dtos.EventTypeDetected,
		UserID:           userID,
		CreatedByVexRule: createdByRule,
		UserAgent:        &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)

	m := riskCalculationReport.Map()
	m["scannerID"] = scannerID

	ev.SetArbitraryJSONData(m)

	return ev
}

func NewMitigateEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID string, justification string, arbitraryData map[string]any, userAgent string) VulnEvent {
	ev := VulnEvent{
		Type:          dtos.EventTypeMitigate,
		UserID:        userID,
		Justification: &justification,
		UserAgent:     &userAgent,
	}
	SetVulnIDOnEvent(&ev, vulnID, vulnType)
	ev.SetArbitraryJSONData(arbitraryData)
	return ev
}

func NewRawRiskAssessmentUpdatedEvent(vulnID uuid.UUID, vulnType dtos.VulnType, userID string, justification string, oldRisk *float64, report dtos.RiskCalculationReport) VulnEvent {
	event := VulnEvent{
		Type:          dtos.EventTypeRawRiskAssessmentUpdated,
		UserID:        userID,
		Justification: &justification,
	}
	SetVulnIDOnEvent(&event, vulnID, vulnType)
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
