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
		ID:                     r.ID,
		AssetVersionName:       r.AssetVersionName,
		AssetID:                r.AssetID.String(),
		State:                  r.State,
		CreatedAt:              r.CreatedAt,
		TicketID:               r.TicketID,
		TicketURL:              r.TicketURL,
		ManualTicketCreation:   r.ManualTicketCreation,
		PolicyID:               r.PolicyID,
		PolicyTitle:            r.PolicyTitle,
		PolicyDescription:      r.PolicyDescription,
		PolicyRelatedResources: r.PolicyRelatedResources,
		PolicyTags:             r.PolicyTags,
		PolicyPriority:         r.PolicyPriority,
		PolicyFrameworks:       r.PolicyFrameworks,
		EvidenceType:           r.EvidenceType,
		Violations:             r.Violations,
		Artifacts:              artifacts,
		Message:                r.Message,
	}
}
