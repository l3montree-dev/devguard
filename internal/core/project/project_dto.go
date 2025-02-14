// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package project

import (
	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type CreateRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`

	ParentID *uuid.UUID         `json:"parentId"` // if created as a child project
	Type     models.ProjectType `json:"type"`
}

func (p *CreateRequest) ToModel() models.Project {
	// check if valid type
	if p.Type != models.ProjectTypeDefault && p.Type != models.ProjectTypeKubernetesNamespace {
		p.Type = models.ProjectTypeDefault
	}

	return models.Project{Name: p.Name,
		Slug:        slug.Make(p.Name),
		Description: p.Description,

		ParentID: p.ParentID,
		Type:     p.Type,
	}
}

type changeRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=member admin"`
}

type inviteToProjectRequest struct {
	Ids []string `json:"ids" validate:"required"`
}

type patchRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	IsPublic    *bool   `json:"isPublic"`

	Type *models.ProjectType `json:"type"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`
}

func (p *patchRequest) applyToModel(project *models.Project) bool {
	updated := false
	if p.Name != nil {
		project.Name = *p.Name
		project.Slug = slug.Make(*p.Name)
		updated = true
	}
	if p.Description != nil {
		project.Description = *p.Description
		updated = true
	}

	if p.IsPublic != nil {
		project.IsPublic = *p.IsPublic
		updated = true
	}

	if p.Type != nil {
		project.Type = *p.Type
		updated = true
	}

	if p.RepositoryID != nil {
		project.RepositoryID = p.RepositoryID
		updated = true
	}

	if p.RepositoryName != nil {
		project.RepositoryName = p.RepositoryName
		updated = true
	}

	return updated
}

type ProjectDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	IsPublic    bool      `json:"isPublic"`
	Type        string    `json:"type"`

	ParentID *uuid.UUID `json:"parentId"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	Assets []models.Asset `json:"assets"`
}

type projectDetailsDTO struct {
	ProjectDTO
	Members []core.User `json:"members"`
}

func fromModel(project models.Project) ProjectDTO {
	return ProjectDTO{
		ID:          project.ID,
		Name:        project.Name,
		Slug:        project.Slug,
		Description: project.Description,
		IsPublic:    project.IsPublic,
		Type:        string(project.Type),

		ParentID: project.ParentID,

		RepositoryID:   project.RepositoryID,
		RepositoryName: project.RepositoryName,

		Assets: project.Assets,
	}
}
