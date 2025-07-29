package vuln

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LicenseRiskDTO struct {
	ID                   string           `json:"id"`
	ScannerIDs           string           `json:"scannerIds"`
	Message              *string          `json:"message"`
	AssetVersionName     string           `json:"assetVersionName"`
	AssetID              string           `json:"assetId"`
	State                models.VulnState `json:"state"`
	CreatedAt            time.Time        `json:"createdAt"`
	TicketID             *string          `json:"ticketId"`
	TicketURL            *string          `json:"ticketUrl"`
	ManualTicketCreation bool             `json:"manualTicketCreation"`

	FinalLicenseDecision string `json:"finalLicenseDecision"`
	ComponentPurl        string `json:"componentPurl"`
}

type detailedLicenseRiskDTO struct {
	LicenseRiskDTO
	Events []events.VulnEventDTO `json:"events"`
}

func LicenseRiskToDto(f models.LicenseRisk) LicenseRiskDTO {

	return LicenseRiskDTO{
		ID:                   f.ID,
		ScannerIDs:           f.ScannerIDs,
		Message:              f.Message,
		AssetVersionName:     f.AssetVersionName,
		AssetID:              f.AssetID.String(),
		State:                f.State,
		CreatedAt:            f.CreatedAt,
		TicketID:             f.TicketID,
		TicketURL:            f.TicketURL,
		ManualTicketCreation: f.ManualTicketCreation,

		FinalLicenseDecision: f.FinalLicenseDecision,
		ComponentPurl:        f.ComponentPurl,
	}
}
