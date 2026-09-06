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
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/package-url/packageurl-go"
)

// ComponentsToCdx renders stored component metadata for CycloneDX export,
// keyed by component id. A merkle tree carries only ids, so this is what puts
// licenses and types back into an exported document.
func ComponentsToCdx(components []models.Component, licenseOverwrites map[string]string) map[string]cyclonedx.Component {
	result := make(map[string]cyclonedx.Component, len(components))
	for _, component := range components {
		// reuse the edge renderer so licenses resolve identically to before,
		// including the component project fallback
		cdxComponent, err := models.ComponentDependency{
			DependencyID: component.ID,
			Dependency:   component,
		}.ToCdxComponent(licenseOverwrites)
		if err != nil {
			continue
		}
		result[component.ID] = cdxComponent
	}
	return result
}

// LicenseDistribution counts how often each license appears among the given
// components. A component counts once however many SBOMs report it.
func LicenseDistribution(components map[string]cyclonedx.Component, componentIDs []string) map[string]int {
	counts := map[string]int{}
	for _, id := range componentIDs {
		component, ok := components[id]
		if !ok || component.Licenses == nil {
			continue
		}
		for _, choice := range *component.Licenses {
			switch {
			case choice.License != nil && choice.License.ID != "":
				counts[choice.License.ID]++
			case choice.License != nil && choice.License.Name != "":
				counts[choice.License.Name]++
			case choice.Expression != "":
				counts[choice.Expression]++
			}
		}
	}
	return counts
}

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

	parsed, err := packageurl.FromString(m.ID)
	if err != nil {
		return dtos.ComponentDTO{
			Purl:                m.ID,
			Dependencies:        []dtos.ComponentDependencyDTO{}, // never populated: a component row carries no edges
			ComponentType:       m.ComponentType,
			Version:             "",
			License:             m.License,
			Published:           m.Published,
			ComponentProject:    componentProject,
			ComponentProjectKey: m.ComponentProjectKey,
		}
	}

	return dtos.ComponentDTO{
		Purl:                m.ID,
		Dependencies:        []dtos.ComponentDependencyDTO{}, // never populated: a component row carries no edges
		ComponentType:       m.ComponentType,
		Version:             parsed.Version,
		License:             m.License,
		Published:           m.Published,
		ComponentProject:    componentProject,
		ComponentProjectKey: m.ComponentProjectKey,
	}
}

func ComponentDependencyToDTO(m models.ComponentDependency) dtos.ComponentDependencyDTO {
	return dtos.ComponentDependencyDTO{
		ComponentPurl:  m.ComponentID,
		DependencyPurl: m.DependencyID,
		Artifacts:      []dtos.ArtifactDTO{}, // Artifacts are now determined via component_id prefix pattern
		Component:      ComponentModelToDTO(m.Component),
		Dependency:     ComponentModelToDTO(m.Dependency),
	}
}

func ComponentOccurrenceToDTO(m models.ComponentOccurrence) dtos.ComponentOccurrenceDTO {
	return dtos.ComponentOccurrenceDTO{
		ComponentDependencyID: m.ComponentDependencyID.String(),
		DependencyPurl:        m.DependencyPurl,
		ProjectID:             m.ProjectID.String(),
		ProjectName:           m.ProjectName,
		ProjectSlug:           m.ProjectSlug,
		AssetID:               m.AssetID.String(),
		AssetName:             m.AssetName,
		AssetSlug:             m.AssetSlug,
		AssetVersionName:      m.AssetVersionName,
		ArtifactName:          m.ArtifactName,
		ArtifactAssetVersion:  m.ArtifactAssetVersion,
	}
}
