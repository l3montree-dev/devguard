package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func ComplianceRiskToDTO(r models.ComplianceRisk) dtos.ComplianceRiskDTO {
	artifacts := make([]dtos.ComplianceRiskArtifactDTO, len(r.Artifacts))
	for i, a := range r.Artifacts {
		artifacts[i] = dtos.ComplianceRiskArtifactDTO{
			ArtifactName:     a.ArtifactName,
			AssetVersionName: a.AssetVersionName,
			AssetID:          a.AssetID.String(),
		}
	}

	return dtos.ComplianceRiskDTO{
		ID:                   r.ID,
		Message:              r.Message,
		AssetVersionName:     r.AssetVersionName,
		AssetID:              r.AssetID.String(),
		State:                r.State,
		CreatedAt:            r.CreatedAt,
		TicketID:             r.TicketID,
		TicketURL:            r.TicketURL,
		ManualTicketCreation: r.ManualTicketCreation,
		PolicyID:             r.PolicyID,
		PredicateType:        r.PredicateType,
		AttestationUpdatedAt: r.AttestationUpdatedAt,
		Artifacts:            artifacts,
	}
}
