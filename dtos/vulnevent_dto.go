package dtos

import (
	"time"

	"github.com/google/uuid"
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

type VulnEventDTO struct {
	ID       uuid.UUID     `json:"id"`
	Type     VulnEventType `json:"type"`
	VulnID   string        `json:"vulnId"`
	VulnType VulnType      `json:"vulnType"`
	UserID   string        `json:"userId"`

	Justification           *string                     `json:"justification"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`

	ArbitraryJSONData map[string]any `json:"arbitraryJSONData"`

	CreatedAt                time.Time `json:"createdAt"`
	OriginalAssetVersionName *string   `json:"originalAssetVersionName,omitempty"`
	VulnerabilityName        string    `json:"vulnerabilityName"`
	PackageName              string    `json:"packageName"`
	URI                      string    `json:"uri"`
	CreatedByVexRule         bool      `json:"createdByVexRule"`
}
