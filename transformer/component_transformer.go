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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

func ComponentModelToDTO(m models.Component) dtos.ComponentDTO {
	var componentProject *dtos.ComponentProjectDTO
	if m.ComponentProject != nil {
		var scoreCard map[string]any
		if m.ComponentProject.ScoreCard != nil {
			scoreCard = *m.ComponentProject.ScoreCard
		}

		componentProject = &dtos.ComponentProjectDTO{
			ProjectKey:      m.ComponentProject.ProjectKey,
			StarsCount:      m.ComponentProject.StarsCount,
			ForksCount:      m.ComponentProject.ForksCount,
			OpenIssuesCount: m.ComponentProject.OpenIssuesCount,
			Homepage:        m.ComponentProject.Homepage,
			License:         m.ComponentProject.License,
			Description:     m.ComponentProject.Description,
			ScoreCard:       scoreCard,
			ScoreCardScore:  m.ComponentProject.ScoreCardScore,
			UpdatedAt:       m.ComponentProject.UpdatedAt,
		}
	}

	return dtos.ComponentDTO{
		Purl:                m.Purl,
		Dependencies:        utils.Map(m.Dependencies, ComponentDependencyToDTO),
		ComponentType:       m.ComponentType,
		Version:             m.Version,
		License:             m.License,
		Published:           m.Published,
		ComponentProject:    componentProject,
		ComponentProjectKey: m.ComponentProjectKey,
	}
}

func ComponentDependencyToDTO(m models.ComponentDependency) dtos.ComponentDependencyDTO {
	return dtos.ComponentDependencyDTO{
		ID:             m.ID,
		ComponentPurl:  utils.SafeDereference(m.ComponentPurl),
		DependencyPurl: m.DependencyPurl,
		Artifacts:      utils.Map(m.Artifacts, ArtifactModelToDTO),
		Component:      ComponentModelToDTO(m.Component),
		Dependency:     ComponentModelToDTO(m.Dependency),
	}
}
