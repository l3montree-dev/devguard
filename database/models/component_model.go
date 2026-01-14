// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package models

import (
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
)

type ComponentProject struct {
	// project name like "github.com/facebook/react"
	ProjectKey      string `json:"projectKey" gorm:"primaryKey;column:project_key"`
	StarsCount      int    `json:"starsCount" gorm:"column:stars_count"`
	ForksCount      int    `json:"forksCount" gorm:"column:forks_count"`
	OpenIssuesCount int    `json:"openIssuesCount" gorm:"column:open_issues_count"`
	Homepage        string `json:"homepage"`
	License         string `json:"license"`
	Description     string `json:"description"`

	ScoreCard      *databasetypes.JSONB `json:"scoreCard" gorm:"column:score_card;type:jsonb"`
	ScoreCardScore *float64             `json:"scoreCardScore" gorm:"column:score_card_score"`
	UpdatedAt      time.Time            `json:"updatedAt" gorm:"column:updated_at"`
}

func (c ComponentProject) TableName() string {
	return "component_projects"
}

type Component struct {
	Purl          string                `json:"purl" gorm:"primaryKey;column:purl"`
	Dependencies  []ComponentDependency `json:"dependsOn" gorm:"hasMany;"`
	ComponentType dtos.ComponentType    `json:"componentType"`
	License       *string               `json:"license"`
	Published     *time.Time            `json:"published"`

	ComponentProject     *ComponentProject `json:"project" gorm:"foreignKey:ComponentProjectKey;references:ProjectKey;constraint:OnDelete:CASCADE;"`
	ComponentProjectKey  *string           `json:"projectId" gorm:"column:project_key"`
	IsLicenseOverwritten bool              `json:"isLicenseOverwritten" gorm:"-"`
}

type ComponentDependency struct {
	ID uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	Component      Component `json:"component" gorm:"foreignKey:ComponentPurl;references:Purl;constraint:OnDelete:CASCADE;"`
	ComponentPurl  *string   `json:"componentPurl" gorm:"column:component_purl;index:component_purl_idx"` // will be nil, for direct dependencies
	Dependency     Component `json:"dependency" gorm:"foreignKey:DependencyPurl;references:Purl;constraint:OnDelete:CASCADE;"`
	DependencyPurl string    `json:"dependencyPurl" gorm:"column:dependency_purl;index:dependency_purl_idx"`

	// Foreign key fields for AssetVersion relationship
	AssetVersionName string       `json:"assetVersionName" gorm:"column:asset_version_name;not null;"`
	AssetID          uuid.UUID    `json:"assetId" gorm:"column:asset_id;not null;type:uuid;"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	Artifacts []Artifact `json:"artifacts" gorm:"many2many:artifact_component_dependencies;constraint:OnDelete:CASCADE"`
}

const Root string = "root"

type ComponentDependencyNode struct {
	ID string `json:"id"`
}

func (c ComponentDependencyNode) GetID() string {
	return c.ID
}

func (c ComponentDependency) ToNodes() []ComponentDependencyNode {
	// a component dependency represents an edge in the dependency tree
	// thus we can represent it as two nodes
	return []ComponentDependencyNode{ComponentDependencyNode{ID: utils.SafeDereference(c.ComponentPurl)}, ComponentDependencyNode{ID: c.DependencyPurl}}
}

func resolveLicense(component ComponentDependency, componentLicenseOverwrites map[string]string) cyclonedx.Licenses {
	licenses := cyclonedx.Licenses{}
	//first check if the license is overwritten by a license risk#
	overwrite, exists := componentLicenseOverwrites[component.DependencyPurl]
	componentLicense := utils.SafeDereference(component.Dependency.License)
	if exists && overwrite != "" {
		// TO-DO: check if the license provided by the user is a valid license or not
		licenses = append(licenses, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				ID: overwrite,
			},
		})

	} else if componentLicense != "" {
		// non-standard and unknown are not valid values for the ID property in licenses
		if componentLicense != "non-standard" && componentLicense != "unknown" {
			// if we have an license expression containing logical operators like OR, AND we need to put them in the expression property instead of id
			if isLicenseExpression(componentLicense) {
				licenses = append(licenses, cyclonedx.LicenseChoice{
					Expression: componentLicense,
				})
			} else {
				licenses = append(licenses, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						ID: componentLicense,
					},
				})
			}

		} else {
			licenses = append(licenses, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					Name: componentLicense,
				},
			})
		}

	} else if component.Dependency.ComponentProject != nil && component.Dependency.ComponentProject.License != "" {
		componentProjectLicense := component.Dependency.ComponentProject.License
		// non-standard and unknown are not valid values for the ID property in licenses
		if componentProjectLicense != "non-standard" && componentProjectLicense != "unknown" {
			// if we have an license expression containing logical operators like OR, AND we need to put them in the expression property instead of id
			if isLicenseExpression(componentProjectLicense) {
				licenses = append(licenses, cyclonedx.LicenseChoice{
					Expression: componentProjectLicense,
				})
			} else {
				licenses = append(licenses, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						ID: componentProjectLicense,
					},
				})
			}

		} else {
			licenses = append(licenses, cyclonedx.LicenseChoice{
				License: &cyclonedx.License{
					Name: componentProjectLicense,
				},
			})
		}
	}
	return licenses
}

func isLicenseExpression(license string) bool {
	return strings.Contains(license, "AND") || strings.Contains(license, "OR") || strings.Contains(license, "WITH")
}

func (c ComponentDependency) ToCdxComponent(componentLicenseOverwrites map[string]string) cyclonedx.Component {
	licenses := resolveLicense(c, componentLicenseOverwrites)
	// parse the purl to set the version column
	parsed, err := packageurl.FromString(c.DependencyPurl)
	if err == nil {
		return cyclonedx.Component{
			Licenses:   &licenses,
			BOMRef:     c.DependencyPurl,
			Type:       cyclonedx.ComponentType(c.Dependency.ComponentType),
			PackageURL: c.DependencyPurl,
			Version:    "",
			Name:       c.DependencyPurl,
		}
	}
	return cyclonedx.Component{
		Licenses:   &licenses,
		BOMRef:     c.DependencyPurl,
		Type:       cyclonedx.ComponentType(c.Dependency.ComponentType),
		PackageURL: c.DependencyPurl,
		Version:    parsed.Version,
		Name:       c.DependencyPurl,
	}
}

func (c ComponentDependency) GetPurl() string {
	return c.DependencyPurl
}

func (c ComponentDependency) GetDependentPurl() *string {
	return c.ComponentPurl
}

func BuildDepMap(deps []ComponentDependency) map[string][]string {
	depMap := make(map[string][]string)
	for _, dep := range deps {
		if _, ok := depMap[utils.SafeDereference(dep.ComponentPurl)]; !ok {
			depMap[utils.SafeDereference(dep.ComponentPurl)] = []string{}
		}
		depMap[utils.SafeDereference(dep.ComponentPurl)] = append(depMap[utils.SafeDereference(dep.ComponentPurl)], dep.DependencyPurl)
	}
	return depMap
}

const NoVersion = "0.0.0"

func GetOnlyDirectDependencies(deps []ComponentDependency) []ComponentDependency {
	return utils.Filter(deps, func(dep ComponentDependency) bool {
		return dep.ComponentPurl == nil
	})
}

func (c Component) TableName() string {
	return "components"
}

func (c ComponentDependency) TableName() string {
	return "component_dependencies"
}

type VulnInPackage struct {
	CVEID        string
	CVE          CVE
	Purl         packageurl.PackageURL
	FixedVersion *string
}

type ComponentOccurrence struct {
	ComponentDependencyID uuid.UUID `json:"componentDependencyId" gorm:"column:component_dependency_id"`
	DependencyPurl        *string   `json:"dependencyPurl" gorm:"column:dependency_purl"`
	ProjectID             uuid.UUID `json:"projectId" gorm:"column:project_id"`
	ProjectName           string    `json:"projectName" gorm:"column:project_name"`
	ProjectSlug           string    `json:"projectSlug" gorm:"column:project_slug"`
	AssetID               uuid.UUID `json:"assetId" gorm:"column:asset_id"`
	AssetName             string    `json:"assetName" gorm:"column:asset_name"`
	AssetSlug             string    `json:"assetSlug" gorm:"column:asset_slug"`
	AssetVersionName      string    `json:"assetVersionName" gorm:"column:asset_version_name"`
	ArtifactName          *string   `json:"artifactName" gorm:"column:artifact_name"`
	ArtifactAssetVersion  *string   `json:"artifactAssetVersion" gorm:"column:artifact_asset_version_name"`
}
