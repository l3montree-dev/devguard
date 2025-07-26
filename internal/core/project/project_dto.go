// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type CreateRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`

	ParentID *uuid.UUID         `json:"parentId"` // if created as a child project
	Type     models.ProjectType `json:"type"`
}

func (projectCreate *CreateRequest) ToModel() models.Project {
	// check if valid type
	if projectCreate.Type != models.ProjectTypeDefault && projectCreate.Type != models.ProjectTypeKubernetesNamespace {
		projectCreate.Type = models.ProjectTypeDefault
	}

	return models.Project{Name: projectCreate.Name,
		Slug:        slug.Make(projectCreate.Name),
		Description: projectCreate.Description,

		ParentID: projectCreate.ParentID,
		Type:     projectCreate.Type,
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

	RepositoryID   *string         `json:"repositoryId"`
	RepositoryName *string         `json:"repositoryName"`
	ConfigFiles    *map[string]any `json:"configFiles"`
}

func (projectPatch *patchRequest) applyToModel(project *models.Project) bool {
	updated := false
	if projectPatch.Name != nil {
		project.Name = *projectPatch.Name
		project.Slug = slug.Make(*projectPatch.Name)
		updated = true
	}
	if projectPatch.Description != nil {
		project.Description = *projectPatch.Description
		updated = true
	}

	if projectPatch.IsPublic != nil {
		project.IsPublic = *projectPatch.IsPublic
		updated = true
	}

	if projectPatch.Type != nil {
		project.Type = *projectPatch.Type
		updated = true
	}

	if projectPatch.RepositoryID != nil {
		project.RepositoryID = projectPatch.RepositoryID
		updated = true
	}

	if projectPatch.RepositoryName != nil {
		project.RepositoryName = projectPatch.RepositoryName
		updated = true
	}

	if projectPatch.ConfigFiles != nil {
		updated = true
		project.ConfigFiles = *projectPatch.ConfigFiles
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

	ParentID *uuid.UUID  `json:"parentId"`
	Parent   *ProjectDTO `json:"parent,omitempty"` // recursive structure

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	Assets      []models.Asset `json:"assets"`
	ConfigFiles map[string]any `json:"configFiles"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"` // only set if this is an external entity
}

type projectDetailsDTO struct {
	ProjectDTO
	Members  []core.User                    `json:"members"`
	Webhooks []common.WebhookIntegrationDTO `json:"webhooks"`
}

func fromModel(project models.Project) ProjectDTO {
	var parentDTO *ProjectDTO
	if project.Parent != nil {
		parentDTO = utils.Ptr(fromModel(*project.Parent))
	}

	return ProjectDTO{
		ID:          project.ID,
		Name:        project.Name,
		Slug:        project.Slug,
		Description: project.Description,
		IsPublic:    project.IsPublic,
		Type:        string(project.Type),

		ParentID: project.ParentID,
		Parent:   parentDTO,

		Assets:      project.Assets,
		ConfigFiles: project.ConfigFiles,

		ExternalEntityProviderID: project.ExternalEntityProviderID,
		ExternalEntityID:         project.ExternalEntityID,
	}
}
