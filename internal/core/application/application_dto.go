package application

import (
	"github.com/google/uuid"
	"github.com/gosimple/slug"
)

type CreateRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
}

func (a *CreateRequest) ToModel(projectID uuid.UUID) Model {
	return Model{
		Name:        a.Name,
		Slug:        slug.Make(a.Name),
		ProjectID:   projectID,
		Description: a.Description,
	}
}
