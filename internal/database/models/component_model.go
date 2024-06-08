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
	"github.com/l3montree-dev/flawfix/internal/utils"
)

type Component struct {
	// either cpe or purl is set
	PurlOrCpe    string                `json:"purlOrCpe" gorm:"primaryKey;column:purl_or_cpe"`
	Dependencies []ComponentDependency `json:"dependsOn" gorm:"hasMany;"`
}

type ComponentDependency struct {
	ID uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`

	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	AssetSemverStart        string    `json:"semverStart" gorm:"column:semver_start;type:semver"`
	AssetSemverEnd          *string   `json:"semverEnd" gorm:"column:semver_end;type:semver"`
	Component               Component `json:"component" gorm:"foreignKey:ComponentPurlOrCpe;references:PurlOrCpe"`
	ComponentPurlOrCpe      string    `json:"componentPurlOrCpe" gorm:"column:component_purl_or_cpe;"`
	Dependency              Component `json:"dependency" gorm:"foreignKey:DependencyPurlOrCpe;references:PurlOrCpe"`
	DependencyPurlOrCpe     string    `json:"dependencyPurlOrCpe" gorm:"column:dependency_purl_or_cpe;"`
	AssetID                 uuid.UUID `json:"assetId" gorm:"column:asset_id;type:uuid;"`
	Asset                   Asset     `json:"asset" gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE;"`
	IsDirectAssetDependency bool      `json:"isDirectAssetDependency" gorm:"column:is_direct_asset_dependency"`

	Depth int `json:"depth" gorm:"column:depth"`
}

const LatestVersion = "latest"

func FlatDependencyGraph(deps []ComponentDependency) []ComponentDependency {
	var flatDeps []ComponentDependency
	for _, dep := range deps {
		flatDeps = append(flatDeps, dep)
		flatDeps = append(flatDeps, FlatDependencyGraph(dep.Dependency.Dependencies)...)
	}
	return flatDeps
}

func GetOnlyDirectDependencies(deps []ComponentDependency) []ComponentDependency {
	return utils.Filter(deps, func(dep ComponentDependency) bool {
		return dep.IsDirectAssetDependency
	})
}

func (c Component) TableName() string {
	return "components"
}

func (c ComponentDependency) TableName() string {
	return "component_dependencies"
}

type VulnInPackage struct {
	CVEID             string
	CVE               CVE
	FixedVersion      *string
	IntroducedVersion *string
	PackageName       string
	PurlWithVersion   string
}

func (v VulnInPackage) GetIntroducedVersion() string {
	if v.IntroducedVersion != nil {
		return *v.IntroducedVersion
	}
	return ""
}

func (v VulnInPackage) GetFixedVersion() string {
	if v.FixedVersion != nil {
		return *v.FixedVersion
	}
	return ""
}
