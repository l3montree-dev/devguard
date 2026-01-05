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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

// MaliciousPackage stores metadata for malicious packages from OSV
type MaliciousPackage struct {
	ID        string    `gorm:"primarykey;type:varchar(255)" json:"id"` // OSV ID
	Summary   string    `gorm:"type:text" json:"summary"`
	Details   string    `gorm:"type:text" json:"details"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	MaliciousAffectedComponents []MaliciousAffectedComponent `json:"affectedComponents" gorm:"foreignKey:MaliciousPackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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

// AffectedComponentBase contains common fields for both CVE and malicious package affected components
type AffectedComponentBase struct {
	PurlWithoutVersion string  `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem          string  `json:"ecosystem" gorm:"type:text;"`
	Scheme             string  `json:"scheme" gorm:"type:text;"`
	Type               string  `json:"type" gorm:"type:text;"`
	Name               string  `json:"name" gorm:"type:text;"`
	Namespace          *string `json:"namespace" gorm:"type:text;"`
	Qualifiers         *string `json:"qualifiers" gorm:"type:text;"`
	Subpath            *string `json:"subpath" gorm:"type:text;"`
	Version            *string `json:"version" gorm:"index"`
	SemverIntroduced   *string `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed        *string `json:"semverEnd" gorm:"type:semver;index"`
	VersionIntroduced  *string `json:"versionIntroduced" gorm:"index"`
	VersionFixed       *string `json:"versionFixed" gorm:"index"`
}

func (base AffectedComponentBase) calculateBaseHash(prefix string) string {
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s",
		prefix,
		base.PurlWithoutVersion,
		base.Ecosystem,
		base.Name,
		utils.SafeDereference(base.Namespace),
		utils.SafeDereference(base.Qualifiers),
		utils.SafeDereference(base.Subpath),
		utils.SafeDereference(base.Version),
		utils.SafeDereference(base.SemverIntroduced),
		utils.SafeDereference(base.SemverFixed),
		utils.SafeDereference(base.VersionIntroduced),
		utils.SafeDereference(base.VersionFixed),
	)

	hash := sha256.Sum256([]byte(toHash))
	return hex.EncodeToString(hash[:])[:16]
}

// MaliciousAffectedComponent stores affected component information for malicious packages
type MaliciousAffectedComponent struct {
	ID                 string `json:"id" gorm:"primaryKey;"`
	MaliciousPackageID string `json:"maliciousPackageId" gorm:"index"`
	AffectedComponentBase

	MaliciousPackage MaliciousPackage `json:"maliciousPackage" gorm:"foreignKey:MaliciousPackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func (MaliciousAffectedComponent) TableName() string {
	return "malicious_affected_components"
}

func (mac MaliciousAffectedComponent) CalculateHash() string {
	return mac.calculateBaseHash(mac.MaliciousPackageID)
}

func (mac *MaliciousAffectedComponent) BeforeSave(tx *gorm.DB) error {
	if mac.ID == "" {
		mac.ID = mac.CalculateHash()
	}
	return nil
}

// MaliciousAffectedComponentFromOSV converts OSV data to MaliciousAffectedComponent entries
func MaliciousAffectedComponentFromOSV(osv dtos.OSV, maliciousPackageID string) []MaliciousAffectedComponent {
	affectedComponents := make([]MaliciousAffectedComponent, 0)

	for _, affected := range osv.Affected {
		bases := affectedComponentBaseFromAffected(affected) // malicious packages don't need ecosystem conversion
		for _, base := range bases {
			affectedComponent := MaliciousAffectedComponent{
				MaliciousPackageID:    maliciousPackageID,
				AffectedComponentBase: base,
			}
			affectedComponents = append(affectedComponents, affectedComponent)
		}
	}

	return affectedComponents
}
