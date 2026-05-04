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
	"encoding/binary"
	"fmt"
	"sync"

	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/utils"

	"gorm.io/gorm"
)

type AffectedComponent struct {
	ID int64 `json:"id" gorm:"primaryKey;"`

	PurlWithoutVersion string `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem          string `json:"ecosystem" gorm:"type:text;"`

	Version           *string `json:"version" gorm:"index"` // either version or semver is defined
	SemverIntroduced  *string `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed       *string `json:"semverEnd" gorm:"type:semver;index"`
	VersionIntroduced *string `json:"versionIntroduced" gorm:"index"` // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering
	VersionFixed      *string `json:"versionFixed" gorm:"index"`      // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering

	CVE []CVE `json:"cves" gorm:"many2many:cve_affected_component;constraint:OnDelete:CASCADE"`
}

func (affectedComponent AffectedComponent) TableName() string {
	return "affected_components"
}

func convertToStringMap(jsonb databasetypes.JSONB) map[string]string {
	result := make(map[string]string)
	for key, value := range jsonb {
		result[key] = fmt.Sprintf("%v", value)
	}
	return result
}

func (affectedComponent AffectedComponent) CalculateHash() int64 {

	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s",
		affectedComponent.PurlWithoutVersion,
		affectedComponent.Ecosystem,
		utils.SafeDereference(affectedComponent.Version),
		utils.SafeDereference(affectedComponent.SemverIntroduced),
		utils.SafeDereference(affectedComponent.SemverFixed),
		utils.SafeDereference(affectedComponent.VersionIntroduced),
		utils.SafeDereference(affectedComponent.VersionFixed),
	)

	sum := sha256.Sum256([]byte(toHash))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func (affectedComponent *AffectedComponent) BeforeSave(tx *gorm.DB) error {
	if affectedComponent.ID == 0 {
		affectedComponent.ID = affectedComponent.CalculateHash()
	}
	return nil
}

var hashBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 512)
		return &b
	},
}

// CalculateHashFast produces the same hash as CalculateHash but avoids
// fmt.Sprintf and the intermediate convertToStringMap allocation.
func (affectedComponent AffectedComponent) CalculateHashFast() int64 {
	bufPtr := hashBufferPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]

	buf = append(buf, affectedComponent.PurlWithoutVersion...)
	buf = append(buf, '/')
	buf = append(buf, affectedComponent.Ecosystem...)
	buf = append(buf, '/')
	if affectedComponent.Version != nil {
		buf = append(buf, *affectedComponent.Version...)
	}
	buf = append(buf, '/')
	if affectedComponent.SemverIntroduced != nil {
		buf = append(buf, *affectedComponent.SemverIntroduced...)
	}
	buf = append(buf, '/')
	if affectedComponent.SemverFixed != nil {
		buf = append(buf, *affectedComponent.SemverFixed...)
	}
	buf = append(buf, '/')
	if affectedComponent.VersionIntroduced != nil {
		buf = append(buf, *affectedComponent.VersionIntroduced...)
	}
	buf = append(buf, '/')
	if affectedComponent.VersionFixed != nil {
		buf = append(buf, *affectedComponent.VersionFixed...)
	}

	sum := sha256.Sum256(buf)
	out := int64(binary.BigEndian.Uint64(sum[:8]))

	*bufPtr = buf[:0]
	hashBufferPool.Put(bufPtr)
	return out
}
