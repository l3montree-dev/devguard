package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func ComplianceRiskToDTO(r models.ComplianceRisk) dtos.ComplianceRiskDTO {
	artifacts := make([]dtos.ArtifactDTO, len(r.Artifacts))
	for i, a := range r.Artifacts {
		artifacts[i] = dtos.ArtifactDTO{
			ArtifactName:     a.ArtifactName,
			AssetVersionName: a.AssetVersionName,
			AssetID:          a.AssetID,
		}
	}

	return dtos.ComplianceRiskDTO{
		ID:                    r.ID,
		AssetVersionName:      r.AssetVersionName,
		AssetID:               r.AssetID.String(),
		State:                 r.State,
		CreatedAt:             r.CreatedAt,
		TicketID:              r.TicketID,
		TicketURL:             r.TicketURL,
		ManualTicketCreation:  r.ManualTicketCreation,
		PolicyID:              r.PolicyID,
		PolicyTitle:           r.PolicyTitle,
		PolicyDescription:     r.PolicyDescription,
		PredicateType:         r.PredicateType,
		AttestationViolations: r.AttestationViolations,
		AttestationUpdatedAt:  r.AttestationUpdatedAt,
		Artifacts:             artifacts,
	}
}
