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

package models

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

// MaliciousPackage stores metadata for malicious packages from OSV
type MaliciousPackage struct {
	ID                          string                       `gorm:"primarykey;type:varchar(255)" json:"id"` // OSV ID
	ContentHash                 int64                        `gorm:"type:bigint;not null;default:0" json:"contentHash"`
	Summary                     string                       `gorm:"type:text" json:"summary"`
	Details                     string                       `gorm:"type:text" json:"details"`
	Published                   time.Time                    `json:"published"`
	Modified                    time.Time                    `json:"modified"`
	MaliciousAffectedComponents []MaliciousAffectedComponent `json:"affectedComponents" gorm:"foreignKey:MaliciousPackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func (mp MaliciousPackage) CalculateContentHash() int64 {
	h := fmt.Sprintf("%s|%s|%s|%s",
		mp.Summary, mp.Details,
		mp.Published.Format(time.RFC3339),
		mp.Modified.Format(time.RFC3339),
	)
	sum := md5.Sum([]byte(h))
	u := binary.BigEndian.Uint64(sum[:8])
	return int64(u & 0x7fffffffffffffff)
}

func (MaliciousPackage) TableName() string {
	return "malicious_packages"
}

func (mp MaliciousPackage) ToOSV() dtos.OSV {
	return dtos.OSV{
		ID:        mp.ID,
		Summary:   mp.Summary,
		Details:   mp.Details,
		Published: mp.Published,
		Modified:  mp.Modified,
	}
}

// MaliciousAffectedComponent stores affected component information for malicious packages
type MaliciousAffectedComponent struct {
	ID                 string  `json:"id" gorm:"primaryKey;"`
	MaliciousPackageID string  `json:"maliciousPackageId" gorm:"index"`
	PurlWithoutVersion string  `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem          string  `json:"ecosystem" gorm:"type:text;"`
	Version            *string `json:"version" gorm:"index"`
	SemverIntroduced   *string `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed        *string `json:"semverEnd" gorm:"type:semver;index"`
	VersionIntroduced  *string `json:"versionIntroduced" gorm:"index"`
	VersionFixed       *string `json:"versionFixed" gorm:"index"`
}

func (MaliciousAffectedComponent) TableName() string {
	return "malicious_affected_components"
}

func (mac MaliciousAffectedComponent) CalculateHash() string {
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s",
		mac.MaliciousPackageID,
		mac.PurlWithoutVersion,
		mac.Ecosystem,
		utils.SafeDereference(mac.Version),
		utils.SafeDereference(mac.SemverIntroduced),
		utils.SafeDereference(mac.SemverFixed),
		utils.SafeDereference(mac.VersionIntroduced),
		utils.SafeDereference(mac.VersionFixed),
	)

	hash := sha256.Sum256([]byte(toHash))
	return hex.EncodeToString(hash[:])[:16]
}

func (mac *MaliciousAffectedComponent) BeforeSave(tx *gorm.DB) error {
	if mac.ID == "" {
		mac.ID = mac.CalculateHash()
	}
	return nil
}
