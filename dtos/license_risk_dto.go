package dtos

import (
	"time"

	"github.com/l3montree-dev/devguard/licenses"
)

type LicenseRiskArtifactDTO struct {
	ArtifactName     string `json:"artifactName"`
	AssetVersionName string `json:"assetVersionName"`
	AssetID          string `json:"assetId"`
}

type LicenseRiskDTO struct {
	ID                   string    `json:"id"`
	Message              *string   `json:"message"`
	AssetVersionName     string    `json:"assetVersionName"`
	AssetID              string    `json:"assetId"`
	State                VulnState `json:"state"`
	CreatedAt            time.Time `json:"createdAt"`
	TicketID             *string   `json:"ticketId"`
	TicketURL            *string   `json:"ticketUrl"`
	ManualTicketCreation bool      `json:"manualTicketCreation"`

	FinalLicenseDecision *string `json:"finalLicenseDecision"`
	ComponentPurl        string  `json:"componentPurl"`

	Component ComponentDTO             `json:"component"`
	Artifacts []LicenseRiskArtifactDTO `json:"artifacts"`
}

type DetailedLicenseRiskDTO struct {
	LicenseRiskDTO
	Events []VulnEventDTO `json:"events"`
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
