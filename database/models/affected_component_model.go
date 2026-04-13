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
	"sort"
	"sync"

	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"

	"gorm.io/gorm"
)

type AffectedComponent struct {
	ID                 string `json:"id" gorm:"primaryKey;"`
	Source             string
	PurlWithoutVersion string              `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem          string              `json:"ecosystem" gorm:"type:text;"`
	Scheme             string              `json:"scheme" gorm:"type:text;"`
	Type               string              `json:"type" gorm:"type:text;"`
	Name               string              `json:"name" gorm:"type:text;"`
	Namespace          *string             `json:"namespace" gorm:"type:text;"`
	Qualifiers         databasetypes.JSONB `json:"qualifiers" gorm:"type:text;"`
	Subpath            *string             `json:"subpath" gorm:"type:text;"`
	Version            *string             `json:"version" gorm:"index"` // either version or semver is defined
	SemverIntroduced   *string             `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed        *string             `json:"semverEnd" gorm:"type:semver;index"`

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

func (affectedComponent AffectedComponent) CalculateHash() string {

	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s",
		affectedComponent.PurlWithoutVersion,
		affectedComponent.Ecosystem,
		affectedComponent.Name,
		utils.SafeDereference(affectedComponent.Namespace),
		normalize.QualifiersMapToString(convertToStringMap(affectedComponent.Qualifiers)),
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

var hashBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 512)
		return &b
	},
}

// CalculateHashFast produces the same hash as CalculateHash but avoids
// fmt.Sprintf and the intermediate convertToStringMap allocation.
func (affectedComponent AffectedComponent) CalculateHashFast() string {
	bufPtr := hashBufferPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]

	buf = append(buf, affectedComponent.PurlWithoutVersion...)
	buf = append(buf, '/')
	buf = append(buf, affectedComponent.Ecosystem...)
	buf = append(buf, '/')
	buf = append(buf, affectedComponent.Name...)
	buf = append(buf, '/')
	if affectedComponent.Namespace != nil {
		buf = append(buf, *affectedComponent.Namespace...)
	}
	buf = append(buf, '/')
	buf = appendQualifiers(buf, affectedComponent.Qualifiers)
	buf = append(buf, '/')
	if affectedComponent.Subpath != nil {
		buf = append(buf, *affectedComponent.Subpath...)
	}
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
	out := hex.EncodeToString(sum[:8])

	*bufPtr = buf[:0]
	hashBufferPool.Put(bufPtr)

	return out
}

// appendQualifiers mirrors normalize.QualifiersMapToString(convertToStringMap(q))
// but writes directly into buf. Keys are unique in a map, so sorting by key
// yields the same order as sorting "key=value" strings.
func appendQualifiers(buf []byte, q databasetypes.JSONB) []byte {
	if len(q) == 0 {
		return buf
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			buf = append(buf, '&')
		}
		buf = append(buf, k...)
		buf = append(buf, '=')
		switch v := q[k].(type) {
		case string:
			buf = append(buf, v...)
		case nil:
			buf = append(buf, "<nil>"...)
		default:
			buf = append(buf, fmt.Sprintf("%v", v)...)
		}
	}
	return buf
}
