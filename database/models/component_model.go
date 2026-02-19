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
	"fmt"
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
	// ID might be a PURL - but not always. Sometimes it is a file path to a binary or a "fake node" we are adding during normalization
	ID            string                `json:"id" gorm:"primaryKey;column:id"`
	Dependencies  []ComponentDependency `json:"dependsOn" gorm:"hasMany;"`
	ComponentType dtos.ComponentType    `json:"componentType"`
	License       *string               `json:"license"`
	Published     *time.Time            `json:"published"`

	ComponentProject     *ComponentProject `json:"project" gorm:"foreignKey:ComponentProjectKey;references:ProjectKey;constraint:OnDelete:CASCADE;"`
	ComponentProjectKey  *string           `json:"projectId" gorm:"column:project_key"`
	IsLicenseOverwritten bool              `json:"isLicenseOverwritten" gorm:"-"`
}

func (c Component) GetID() (packageurl.PackageURL, error) {
	return packageurl.FromString(c.ID)
}

type ComponentDependency struct {
	ID uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	Component    Component `json:"component" gorm:"foreignKey:ComponentID;references:ID;constraint:OnDelete:CASCADE;"`
	ComponentID  *string   `json:"componentPurl" gorm:"column:component_id;index:component_purl_idx"` // will be nil, for direct dependencies
	Dependency   Component `json:"dependency" gorm:"foreignKey:DependencyID;references:ID;constraint:OnDelete:CASCADE;"`
	DependencyID string    `json:"dependencyPurl" gorm:"column:dependency_id;index:dependency_purl_idx"`

	// Foreign key fields for AssetVersion relationship
	AssetVersionName string       `json:"assetVersionName" gorm:"column:asset_version_name;not null;"`
	AssetID          uuid.UUID    `json:"assetId" gorm:"column:asset_id;not null;type:uuid;"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`
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
	return []ComponentDependencyNode{ComponentDependencyNode{ID: utils.SafeDereference(c.ComponentID)}, ComponentDependencyNode{ID: c.DependencyID}}
}

func resolveLicense(component ComponentDependency, componentLicenseOverwrites map[string]string) cyclonedx.Licenses {
	licenses := cyclonedx.Licenses{}
	//first check if the license is overwritten by a license risk#
	overwrite, exists := componentLicenseOverwrites[component.DependencyID]
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

// isValidCycloneDXComponentType validates that a component type is valid per CycloneDX spec
func isValidCycloneDXComponentType(ct cyclonedx.ComponentType) bool {
	// CycloneDX 1.6 valid component types
	validTypes := map[cyclonedx.ComponentType]bool{
		cyclonedx.ComponentTypeApplication:          true,
		cyclonedx.ComponentTypeContainer:            true,
		cyclonedx.ComponentTypeCryptographicAsset:   true,
		cyclonedx.ComponentTypeData:                 true,
		cyclonedx.ComponentTypeDevice:               true,
		cyclonedx.ComponentTypeDeviceDriver:         true,
		cyclonedx.ComponentTypeFile:                 true,
		cyclonedx.ComponentTypeFirmware:             true,
		cyclonedx.ComponentTypeFramework:            true,
		cyclonedx.ComponentTypeLibrary:              true,
		cyclonedx.ComponentTypeMachineLearningModel: true,
		cyclonedx.ComponentTypeOS:                   true,
		cyclonedx.ComponentTypePlatform:             true,
	}
	return validTypes[ct]
}

// sanitizeCycloneDXComponentType ensures a component type is valid per CycloneDX spec
// If invalid, defaults to Library as a safe fallback
func sanitizeCycloneDXComponentType(ct dtos.ComponentType) cyclonedx.ComponentType {
	cdxType := cyclonedx.ComponentType(ct)
	if isValidCycloneDXComponentType(cdxType) {
		return cdxType
	}
	// Default to Library for unknown types - safe and commonly used
	return cyclonedx.ComponentTypeLibrary
}

func (c ComponentDependency) ToCdxComponent(componentLicenseOverwrites map[string]string) (cyclonedx.Component, error) {
	// DependencyID (used for BOMRef and Name) must not be empty per CycloneDX spec
	if c.DependencyID == "" {
		return cyclonedx.Component{}, fmt.Errorf("DependencyID must not be empty: required for BOMRef and Name per CycloneDX spec")
	}

	licenses := resolveLicense(c, componentLicenseOverwrites)

	// Sanitize component type to ensure it's valid per CycloneDX spec - guarantees spec compliance
	// Only exception to error-first approach: invalid types are sanitized instead of erroring
	componentType := sanitizeCycloneDXComponentType(c.Dependency.ComponentType)
	if !isValidCycloneDXComponentType(componentType) {
		// This should never happen after sanitization, but we enforce it as a safety net
		componentType = cyclonedx.ComponentTypeLibrary
	}

	// parse the purl to set the version column
	parsed, err := packageurl.FromString(c.DependencyID)
	if err != nil {
		// parsing failed - ID is not a valid PURL (e.g., file path or fake node)
		// Return component with empty PackageURL per CycloneDX spec
		return cyclonedx.Component{
			Licenses:   &licenses,
			BOMRef:     c.DependencyID,
			Type:       componentType,
			PackageURL: "", // Empty for non-PURL identifiers
			Version:    "",
			Name:       c.DependencyID,
		}, nil
	}
	// parsing succeeded - use version from PURL
	return cyclonedx.Component{
		Licenses:   &licenses,
		BOMRef:     c.DependencyID,
		Type:       componentType,
		PackageURL: c.DependencyID,
		Version:    parsed.Version,
		Name:       c.DependencyID,
	}, nil
}

func (c ComponentDependency) GetID() string {
	return c.DependencyID
}

func (c ComponentDependency) GetDependentID() *string {
	return c.ComponentID
}

func BuildDepMap(deps []ComponentDependency) map[string][]string {
	depMap := make(map[string][]string)
	for _, dep := range deps {
		if _, ok := depMap[utils.SafeDereference(dep.ComponentID)]; !ok {
			depMap[utils.SafeDereference(dep.ComponentID)] = []string{}
		}
		depMap[utils.SafeDereference(dep.ComponentID)] = append(depMap[utils.SafeDereference(dep.ComponentID)], dep.DependencyID)
	}
	return depMap
}

const NoVersion = "0.0.0"

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
	DependencyPurl        *string   `json:"dependencyPurl" gorm:"column:dependency_id"`
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
