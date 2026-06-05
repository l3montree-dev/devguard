package dtos

import (
	"time"

	"github.com/google/uuid"
)

type ComplianceRiskDTO struct {
	ID                   uuid.UUID `json:"id"`
	Message              *string   `json:"message"`
	AssetVersionName     string    `json:"assetVersionName"`
	AssetID              string    `json:"assetId"`
	State                VulnState `json:"state"`
	CreatedAt            time.Time `json:"createdAt"`
	TicketID             *string   `json:"ticketId"`
	TicketURL            *string   `json:"ticketUrl"`
	ManualTicketCreation bool      `json:"manualTicketCreation"`

	PolicyID             string        `json:"policyId"`
	PolicyName           string        `json:"policyName"`
	PredicateType        string        `json:"predicateType"`
	AttestationUpdatedAt *time.Time    `json:"attestationUpdatedAt"`
	Artifacts            []ArtifactDTO `json:"artifacts,omitempty"`
}

type DetailedComplianceRiskDTO struct {
	ComplianceRiskDTO
	Events []VulnEventDTO `json:"events"`
}
