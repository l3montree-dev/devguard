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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/obj"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

type AffectedComponent struct {
	ID               string `json:"id" gorm:"primaryKey;"`
	Source           string
	PURL             string  `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem        string  `json:"ecosystem" gorm:"type:text;"`
	Scheme           string  `json:"scheme" gorm:"type:text;"`
	Type             string  `json:"type" gorm:"type:text;"`
	Name             string  `json:"name" gorm:"type:text;"`
	Namespace        *string `json:"namespace" gorm:"type:text;"`
	Qualifiers       *string `json:"qualifiers" gorm:"type:text;"`
	Subpath          *string `json:"subpath" gorm:"type:text;"`
	Version          *string `json:"version" gorm:"index"` // either version or semver is defined
	SemverIntroduced *string `json:"semverStart" gorm:"type:semver;index"`
	SemverFixed      *string `json:"semverEnd" gorm:"type:semver;index"`

	VersionIntroduced *string `json:"versionIntroduced" gorm:"index"` // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering
	VersionFixed      *string `json:"versionFixed" gorm:"index"`      // for non semver packages - if both are defined, THIS one should be used for displaying. We might fake semver versions just for database querying and ordering

	CVE []CVE `json:"cves" gorm:"many2many:cve_affected_component;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func (affectedComponent AffectedComponent) TableName() string {
	return "affected_components"
}

func (a AffectedComponent) CalculateHash() string {
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s/%s/%s",
		a.PURL,
		a.Ecosystem,
		a.Name,
		utils.SafeDereference(a.Namespace),
		utils.SafeDereference(a.Qualifiers),
		utils.SafeDereference(a.Subpath),
		utils.SafeDereference(a.Version),
		utils.SafeDereference(a.SemverIntroduced),
		utils.SafeDereference(a.SemverFixed),
		utils.SafeDereference(a.VersionIntroduced),
		utils.SafeDereference(a.VersionFixed),
	)

	hash := sha256.Sum256([]byte(toHash))
	return hex.EncodeToString(hash[:])
}

func (affectedComponent *AffectedComponent) BeforeSave(tx *gorm.DB) error {
	if affectedComponent.ID == "" {
		affectedComponent.ID = affectedComponent.CalculateHash()
	}
	return nil
}

func AffectedComponentFromOSV(osv obj.OSV) []AffectedComponent {
	affectedComponents := make([]AffectedComponent, 0)

	cveIds := osv.GetCVE()
	cves := make([]CVE, len(cveIds))
	for i, cveID := range cveIds {
		cves[i] = CVE{CVE: cveID}
	}

	for _, affected := range osv.Affected {
		// check if the affected package has a purl
		if affected.Package.Purl == "" {
			continue
		}
		if affected.EcosystemSpecific != nil {
			// get the urgency - debian defines it: https://security-team.debian.org/security_tracker.html#severity-levels
			if urgency, ok := affected.EcosystemSpecific["urgency"]; ok {
				if urgencyStr, ok := urgency.(string); ok {
					urgencyStr = strings.ToLower(urgencyStr)
					if urgencyStr == "unimportant" {
						// just continue
						continue
					}
				}
			}
		}
		purl, err := packageurl.FromString(affected.Package.Purl)
		if err != nil {
			slog.Error("could not parse purl", "purl", affected.Package.Purl, "err", err)
			continue
		}
		qualifiersStr := purl.Qualifiers.String()

		// iterate over all ranges
		containsSemver := false
		for _, r := range affected.Ranges {
			if r.Type == "SEMVER" {
				containsSemver = true
			} else {
				continue
			}
			// iterate over all events
			for i, e := range r.Events {
				tmpE := e
				if i%2 != 0 {
					continue
				}

				// check if a fix does even exist
				fixed := ""
				if len(r.Events) != i+1 {
					// there is a fix available
					fixed = r.Events[i+1].Fixed
				}

				var semverIntroducedPtr *string
				var semverFixedPtr *string
				semverIntroduced, err := normalize.SemverFix(tmpE.Introduced)
				if err == nil {
					semverIntroducedPtr = &semverIntroduced
				}
				semverFixed, err := normalize.SemverFix(fixed)
				if err == nil {
					semverFixedPtr = &semverFixed
				}

				// create the affected package
				affectedComponent := AffectedComponent{
					PURL:       strings.Split(affected.Package.Purl, "?")[0],
					Ecosystem:  affected.Package.Ecosystem,
					Scheme:     "pkg",
					Type:       purl.Type,
					Name:       purl.Name,
					Namespace:  &purl.Namespace,
					Qualifiers: &qualifiersStr,
					Subpath:    &purl.Subpath,

					Source: "osv",

					SemverIntroduced: semverIntroducedPtr,
					SemverFixed:      semverFixedPtr,

					CVE: cves,
				}
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		}

		if !containsSemver {
			// create an affected package with a specific version
			for _, v := range affected.Versions {
				tmpV := v
				affectedComponent := AffectedComponent{
					PURL:       strings.Split(affected.Package.Purl, "?")[0],
					Ecosystem:  affected.Package.Ecosystem,
					Scheme:     "pkg",
					Type:       purl.Type,
					Name:       purl.Name,
					Namespace:  &purl.Namespace,
					Qualifiers: &qualifiersStr,
					Subpath:    &purl.Subpath,
					Version:    &tmpV,

					Source: "osv",

					CVE: cves,
				}
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		}
	}
	return affectedComponents
}
