package dtos

import (
	"time"

	"github.com/google/uuid"
)

type PolicyFrameworks struct {
	Framework string   `yaml:"framework" json:"framework"`
	Controls  []string `yaml:"controls"  json:"controls"`
}

type ComplianceRiskDTO struct {
	ID               uuid.UUID     `json:"id"`
	AssetVersionName string        `json:"assetVersionName"`
	AssetID          string        `json:"assetId"`
	Artifacts        []ArtifactDTO `json:"artifacts,omitempty"`

	PolicyID               string             `json:"policyId"`
	PolicyTitle            string             `json:"policyTitle"`
	PolicyDescription      *string            `json:"policyDescription"`
	PolicyRelatedResources []string           `json:"policyRelatedResources"`
	PolicyTags             []string           `json:"policyTags"`
	PolicyPriority         int                `json:"policyPriority"`
	PolicyFrameworks       []PolicyFrameworks `json:"policyFrameworks"`

	State                VulnState `json:"state"`
	CreatedAt            time.Time `json:"createdAt"`
	TicketID             *string   `json:"ticketId"`
	TicketURL            *string   `json:"ticketUrl"`
	ManualTicketCreation bool      `json:"manualTicketCreation"`

	Message      string   `json:"message"`
	EvidenceType string   `json:"evidenceType"`
	Violations   []string `json:"violations"`
}

type DetailedComplianceRiskDTO struct {
	ComplianceRiskDTO
	Events []VulnEventDTO `json:"events"`
}
