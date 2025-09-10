package vuln

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LicenseRiskDTO struct {
	ID                   string           `json:"id"`
	Message              *string          `json:"message"`
	AssetVersionName     string           `json:"assetVersionName"`
	AssetID              string           `json:"assetId"`
	State                models.VulnState `json:"state"`
	CreatedAt            time.Time        `json:"createdAt"`
	TicketID             *string          `json:"ticketId"`
	TicketURL            *string          `json:"ticketUrl"`
	ManualTicketCreation bool             `json:"manualTicketCreation"`

	FinalLicenseDecision *string `json:"finalLicenseDecision"`
	ComponentPurl        string  `json:"componentPurl"`

	Component models.Component  `json:"component"`
	Artifacts []models.Artifact `json:"artifacts"`
}

type detailedLicenseRiskDTO struct {
	LicenseRiskDTO
	Events []events.VulnEventDTO `json:"events"`
}

func LicenseRiskToDto(f models.LicenseRisk) LicenseRiskDTO {
	return LicenseRiskDTO{
		ID:                   f.ID,
		Artifacts:            f.Artifacts,
		Message:              f.Message,
		AssetVersionName:     f.AssetVersionName,
		AssetID:              f.AssetID.String(),
		State:                f.State,
		CreatedAt:            f.CreatedAt,
		TicketID:             f.TicketID,
		TicketURL:            f.TicketURL,
		ManualTicketCreation: f.ManualTicketCreation,

		FinalLicenseDecision: beautifyFinalLicenseDecision(f.FinalLicenseDecision),
		ComponentPurl:        f.ComponentPurl,
		Component:            f.Component,
	}
}

func beautifyFinalLicenseDecision(licenseDecision *string) *string {
	if licenseDecision == nil {
		return nil
	}
	if val, ok := component.LicenseMap[*licenseDecision]; ok {
		return &val.Name
	}
	return licenseDecision
}
