package dtos

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/licenses"
)

type LicenseRiskArtifact struct {
	ArtifactName     string `json:"artifactName"`
	AssetVersionName string `json:"assetVersionName"`
	AssetID          string `json:"assetId"`
}

type LicenseRisk struct {
	ID                   uuid.UUID `json:"id"`
	AssetVersionName     string    `json:"assetVersionName"`
	AssetID              string    `json:"assetId"`
	State                VulnState `json:"state"`
	CreatedAt            time.Time `json:"createdAt"`
	TicketID             *string   `json:"ticketId"`
	TicketURL            *string   `json:"ticketUrl"`
	ManualTicketCreation bool      `json:"manualTicketCreation"`

	FinalLicenseDecision *string `json:"finalLicenseDecision"`
	ComponentPurl        string  `json:"componentPurl"`

	Component Component             `json:"component"`
	Artifacts []LicenseRiskArtifact `json:"artifacts"`
}

type DetailedLicenseRisk struct {
	LicenseRisk
	Events []VulnEvent `json:"events"`
}

type MakeFinalLicenseDecisionRequest struct {
	License       string `json:"license" validate:"max=256"`
	Justification string `json:"justification" validate:"max=4000"`
}

func BeautifyFinalLicenseDecision(licenseDecision *string) *string {
	if licenseDecision == nil {
		return nil
	}
	if val, ok := licenses.LicenseMap[*licenseDecision]; ok {
		return &val.Name
	}
	return licenseDecision
}
