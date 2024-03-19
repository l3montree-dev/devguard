package asset

import (
	"github.com/google/uuid"
	"github.com/gosimple/slug"
)

type createRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`

	Importance            int  `json:"importance"`
	ReachableFromInternet bool `json:"reachableFromInternet"`

	ConfidentialityRequirement string `json:"confidentialityRequirement" validate:"required"`
	IntegrityRequirement       string `json:"integrityRequirement" validate:"required"`
	AvailabilityRequirement    string `json:"availabilityRequirement" validate:"required"`
}

func sanitizeRequirementLevel(level string) RequirementLevel {
	switch level {
	case "low", "medium", "high":
		return RequirementLevel(level)
	default:
		return "high"
	}
}

func (a *createRequest) toModel(projectID uuid.UUID) Model {
	return Model{
		Name:        a.Name,
		Slug:        slug.Make(a.Name),
		ProjectID:   projectID,
		Description: a.Description,

		Importance:            a.Importance,
		ReachableFromInternet: a.ReachableFromInternet,

		ConfidentialityRequirement: sanitizeRequirementLevel(a.ConfidentialityRequirement),
		IntegrityRequirement:       sanitizeRequirementLevel(a.IntegrityRequirement),
		AvailabilityRequirement:    sanitizeRequirementLevel(a.AvailabilityRequirement),
	}
}
