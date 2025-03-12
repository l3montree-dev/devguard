// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	ID              string `json:"id" gorm:"primaryKey;column:id"`
	StarsCount      int    `json:"starsCount" gorm:"column:stars_count"`
	ForksCount      int    `json:"forksCount" gorm:"column:forks_count"`
	OpenIssuesCount int    `json:"openIssuesCount" gorm:"column:open_issues_count"`
	Homepage        string `json:"homepage"`
	License         string `json:"license"`
	Description     string `json:"description"`

	ScoreCard database.JSONB `json:"scoreCard" gorm:"column:score_card"`
}

type Component struct {
	Purl          string                `json:"purl" gorm:"primaryKey;column:purl"` // without qualifiers!
	Dependencies  []ComponentDependency `json:"dependsOn" gorm:"hasMany;"`
	ComponentType ComponentType         `json:"componentType"`
	Version       string                `json:"version"`
	License       string                `json:"license" default:"unknown"`

	ComponentProject   *ComponentProject `json:"project" gorm:"foreignKey:ID;references:ComponentProjectID;constraint:OnDelete:CASCADE;"`
	ComponentProjectID string            `json:"projectId" gorm:"column:project_id"`
}

type ComponentDependency struct {
	ID uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`

	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	AssetSemverStart string       `json:"semverStart" gorm:"column:semver_start;type:semver"`
	AssetSemverEnd   *string      `json:"semverEnd" gorm:"column:semver_end;type:semver"`
	Component        Component    `json:"component" gorm:"foreignKey:ComponentPurl;references:Purl"`
	ComponentPurl    *string      `json:"componentPurl" gorm:"column:component_purl;"` // will be nil, for direct dependencies
	Dependency       Component    `json:"dependency" gorm:"foreignKey:DependencyPurl;references:Purl"`
	DependencyPurl   string       `json:"dependencyPurl" gorm:"column:dependency_purl;"`
	AssetID          uuid.UUID    `json:"assetVersionId"`
	AssetVersionName string       `json:"assetVersionName"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetID,AssetVersionName;references:AssetID,Name;constraint:OnDelete:CASCADE;"`

	ScannerID string `json:"scannerId" gorm:"column:scanner_id"` // the id of the scanner

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
