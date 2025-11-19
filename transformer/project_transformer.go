// Copyright (C) 2025 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package transformer

import (
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

func ProjectCreateRequestToModel(projectCreate dtos.ProjectCreateRequest) models.Project {
	// check if valid type
	projectType := projectCreate.Type
	if projectType != string(models.ProjectTypeDefault) && projectType != string(models.ProjectTypeKubernetesNamespace) {
		projectType = string(models.ProjectTypeDefault)
	}

	return models.Project{
		Name:        projectCreate.Name,
		Slug:        slug.Make(projectCreate.Name),
		Description: projectCreate.Description,
		ParentID:    projectCreate.ParentID,
		Type:        models.ProjectType(projectType),
	}
}

func ApplyProjectPatchRequestToModel(projectPatch dtos.ProjectPatchRequest, project *models.Project) bool {
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
		project.Type = models.ProjectType(*projectPatch.Type)
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

func ProjectModelToDTO(project models.Project) dtos.ProjectDTO {
	var parentDTO *dtos.ProjectDTO
	if project.Parent != nil {
		parentDTO = utils.Ptr(ProjectModelToDTO(*project.Parent))
	}

	assets := make([]dtos.AssetDTO, len(project.Assets))
	for i, asset := range project.Assets {
		assets[i] = AssetModelToDTO(asset)
	}

	return dtos.ProjectDTO{
		Avatar:                   project.Avatar,
		ID:                       project.ID,
		Name:                     project.Name,
		Slug:                     project.Slug,
		Description:              project.Description,
		IsPublic:                 project.IsPublic,
		Type:                     string(project.Type),
		ParentID:                 project.ParentID,
		Parent:                   parentDTO,
		RepositoryID:             project.RepositoryID,
		RepositoryName:           project.RepositoryName,
		Assets:                   assets,
		ConfigFiles:              project.ConfigFiles,
		ExternalEntityProviderID: project.ExternalEntityProviderID,
		ExternalEntityID:         project.ExternalEntityID,
	}
}
