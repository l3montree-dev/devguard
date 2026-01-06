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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/l3montree-dev/devguard/utils"

	"gorm.io/gorm"
)

type AffectedComponent struct {
	ID                 string `json:"id" gorm:"primaryKey;"`
	Source             string
	PurlWithoutVersion string  `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem          string  `json:"ecosystem" gorm:"type:text;"`
	Scheme             string  `json:"scheme" gorm:"type:text;"`
	Type               string  `json:"type" gorm:"type:text;"`
	Name               string  `json:"name" gorm:"type:text;"`
	Namespace          *string `json:"namespace" gorm:"type:text;"`
	Qualifiers         *string `json:"qualifiers" gorm:"type:text;"`
	Subpath            *string `json:"subpath" gorm:"type:text;"`
	Version            *string `json:"version" gorm:"index"` // either version or semver is defined
	SemverIntroduced   *string `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed        *string `json:"semverEnd" gorm:"type:semver;index"`

	VersionIntroduced *string `json:"versionIntroduced" gorm:"index"` // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering
	VersionFixed      *string `json:"versionFixed" gorm:"index"`      // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering

	CVE []CVE `json:"cves" gorm:"many2many:cve_affected_component"`
}

func (affectedComponent AffectedComponent) TableName() string {
	return "affected_components"
}

func (affectedComponent AffectedComponent) CalculateHash() string {
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s",
		affectedComponent.PurlWithoutVersion,
		affectedComponent.Ecosystem,
		affectedComponent.Name,
		utils.SafeDereference(affectedComponent.Namespace),
		utils.SafeDereference(affectedComponent.Qualifiers),
		utils.SafeDereference(affectedComponent.Subpath),
		utils.SafeDereference(affectedComponent.Version),
		utils.SafeDereference(affectedComponent.SemverIntroduced),
		utils.SafeDereference(affectedComponent.SemverFixed),
		utils.SafeDereference(affectedComponent.VersionIntroduced),
		utils.SafeDereference(affectedComponent.VersionFixed),
	)

	hash := sha256.Sum256([]byte(toHash))
	return hex.EncodeToString(hash[:])[:16]
}

func (affectedComponent *AffectedComponent) BeforeSave(tx *gorm.DB) error {
	if affectedComponent.ID == "" {
		affectedComponent.ID = affectedComponent.CalculateHash()
	}
	return nil
}
