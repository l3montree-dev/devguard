package dtos

import (
	"time"

	"github.com/google/uuid"
)

type ComplianceRiskDTO struct {
	ID               uuid.UUID     `json:"id"`
	AssetVersionName string        `json:"assetVersionName"`
	AssetID          string        `json:"assetId"`
	Artifacts        []ArtifactDTO `json:"artifacts,omitempty"`

	PolicyID          string  `json:"policyId"`
	PolicyTitle       string  `json:"policyTitle"`
	PolicyDescription *string `json:"policyDescription"`

	State                VulnState `json:"state"`
	CreatedAt            time.Time `json:"createdAt"`
	TicketID             *string   `json:"ticketId"`
	TicketURL            *string   `json:"ticketUrl"`
	ManualTicketCreation bool      `json:"manualTicketCreation"`

	PredicateType         string     `json:"predicateType"`
	AttestationUpdatedAt  *time.Time `json:"attestationUpdatedAt"`
	AttestationViolations []string   `json:"attestationViolations"`
}

type DetailedComplianceRiskDTO struct {
	ComplianceRiskDTO
	Events []VulnEventDTO `json:"events"`
}
