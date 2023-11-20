package dto

import (
	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/flawfix/internal/models"
)

type ApplicationCreateRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
}

func (a *ApplicationCreateRequest) ToModel(projectID uuid.UUID) models.Application {
	return models.Application{
		Name:        a.Name,
		Slug:        slug.Make(a.Name),
		ProjectID:   projectID,
		Description: a.Description,
	}
}
