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
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type ComponentType string

const (
	ComponentTypeApplication          ComponentType = "application"
	ComponentTypeContainer            ComponentType = "container"
	ComponentTypeData                 ComponentType = "data"
	ComponentTypeDevice               ComponentType = "device"
	ComponentTypeDeviceDriver         ComponentType = "device-driver"
	ComponentTypeFile                 ComponentType = "file"
	ComponentTypeFirmware             ComponentType = "firmware"
	ComponentTypeFramework            ComponentType = "framework"
	ComponentTypeLibrary              ComponentType = "library"
	ComponentTypeMachineLearningModel ComponentType = "machine-learning-model"
	ComponentTypeOS                   ComponentType = "operating-system"
	ComponentTypePlatform             ComponentType = "platform"
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

	ScoreCard      *database.JSONB `json:"scoreCard" gorm:"column:score_card;type:jsonb"`
	ScoreCardScore *float64        `json:"scoreCardScore" gorm:"column:score_card_score"`
	UpdatedAt      time.Time       `json:"updatedAt" gorm:"column:updated_at"`
}

func (c ComponentProject) TableName() string {
	return "component_projects"
}

type Component struct {
	Purl          string                `json:"purl" gorm:"primaryKey;column:purl"` // without qualifiers!
	Dependencies  []ComponentDependency `json:"dependsOn" gorm:"hasMany;"`
	ComponentType ComponentType         `json:"componentType"`
	Version       string                `json:"version"`
	License       *string               `json:"license"`
	Published     *time.Time            `json:"published"`

	ComponentProject     *ComponentProject `json:"project" gorm:"foreignKey:ComponentProjectKey;references:ProjectKey;constraint:OnDelete:CASCADE;"`
	ComponentProjectKey  *string           `json:"projectId" gorm:"column:project_key"`
	IsLicenseOverwritten bool              `json:"isLicenseOverwritten" gorm:"sql:-"`
}

type ComponentDependency struct {
	ID uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	Component        Component    `json:"component" gorm:"foreignKey:ComponentPurl;references:Purl;constraint:OnDelete:CASCADE;"`
	ComponentPurl    *string      `json:"componentPurl" gorm:"column:component_purl;"` // will be nil, for direct dependencies
	Dependency       Component    `json:"dependency" gorm:"foreignKey:DependencyPurl;references:Purl;constraint:OnDelete:CASCADE;"`
	DependencyPurl   string       `json:"dependencyPurl" gorm:"column:dependency_purl;"`
	AssetID          uuid.UUID    `json:"assetVersionId"`
	AssetVersionName string       `json:"assetVersionName"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetID,AssetVersionName;references:AssetID,Name;constraint:OnDelete:CASCADE;"`

	ScannerIDs string `json:"scannerIds" gorm:"column:scanner_ids"`

	Depth int `json:"depth" gorm:"column:depth"`
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
	Purl         string
	FixedVersion *string
}
