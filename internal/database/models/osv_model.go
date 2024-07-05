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
	"time"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
)

type pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type semverEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type rng struct {
	Type   string        `json:"type"`
	Events []semverEvent `json:"events"`
}

type Affected struct {
	Package          pkg      `json:"package"`
	Ranges           []rng    `json:"ranges"`
	Versions         []string `json:"versions"`
	DatabaseSpecific struct {
		Source string `json:"source"`
	} `json:"database_specific"`
}

type OSV struct {
	ID            string     `json:"id"`
	Summary       string     `json:"summary"`
	Modified      time.Time  `json:"modified"`
	Published     time.Time  `json:"published"`
	Related       []string   `json:"related"`
	Aliases       []string   `json:"aliases"`
	Affected      []Affected `json:"affected"`
	SchemaVersion string     `json:"schema_version"`
}

func (osv OSV) GetCVE() []string {
	cves := make([]string, 0)
	for _, alias := range osv.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cves = append(cves, alias)
		}
	}
	// check if the osv itself is a cve
	if strings.HasPrefix(osv.ID, "CVE-") {
		cves = append(cves, osv.ID)
	}

	return cves
}
func (osv OSV) IsCVE() bool {
	return len(osv.GetCVE()) > 0
}

type AffectedComponent struct {
	ID               string  `json:"id" gorm:"primaryKey;"`
	PURL             string  `json:"purl" gorm:"type:text;column:purl;index"`
	Ecosystem        string  `json:"ecosystem" gorm:"type:text;"`
	Scheme           string  `json:"scheme" gorm:"type:text;"`
	Type             string  `json:"type" gorm:"type:text;"`
	Name             string  `json:"name" gorm:"type:text;"`
	Namespace        *string `json:"namespace" gorm:"type:text;"`
	Qualifiers       *string `json:"qualifiers" gorm:"type:text;"`
	Subpath          *string `json:"subpath" gorm:"type:text;"`
	Version          *string `json:"version" gorm:"index"` // either version or semver is defined
	SemverIntroduced *string `json:"semver_start" gorm:"type:semver;index"`
	SemverFixed      *string `json:"semver_end" gorm:"type:semver;index"`

	CVE []CVE `json:"cves" gorm:"many2many:cve_affected_component;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

func (affectedComponent AffectedComponent) TableName() string {
	return "affected_components"
}

func (affectedComponent *AffectedComponent) SetIdHash() {
	// build the stable map
	toHash := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s",
		affectedComponent.PURL,
		affectedComponent.Ecosystem,
		affectedComponent.Name,
		utils.SafeDereference(affectedComponent.Namespace),
		utils.SafeDereference(affectedComponent.Qualifiers),
		utils.SafeDereference(affectedComponent.Subpath),
		utils.SafeDereference(affectedComponent.Version),
		utils.SafeDereference(affectedComponent.SemverIntroduced),
		utils.SafeDereference(affectedComponent.SemverFixed))

	hash := sha256.Sum256([]byte(toHash))
	hashString := hex.EncodeToString(hash[:])

	affectedComponent.ID = hashString
}

func (osv OSV) GetAffectedPackages() []AffectedComponent {
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
				semverIntroduced, err := utils.SemverFix(tmpE.Introduced)
				if err == nil {
					semverIntroducedPtr = &semverIntroduced
				}
				semverFixed, err := utils.SemverFix(fixed)
				if err == nil {
					semverFixedPtr = &semverFixed
				}

				// create the affected package
				affectedComponent := AffectedComponent{
					PURL:       affected.Package.Purl,
					Ecosystem:  affected.Package.Ecosystem,
					Scheme:     "pkg",
					Type:       purl.Type,
					Name:       purl.Name,
					Namespace:  &purl.Namespace,
					Qualifiers: &qualifiersStr,
					Subpath:    &purl.Subpath,

					SemverIntroduced: semverIntroducedPtr,
					SemverFixed:      semverFixedPtr,

					CVE: cves,
				}
				affectedComponent.SetIdHash()
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		}

		if !containsSemver {
			// create an affected package with a specific version
			for _, v := range affected.Versions {
				tmpV := v
				affectedComponent := AffectedComponent{
					PURL:       affected.Package.Purl,
					Ecosystem:  affected.Package.Ecosystem,
					Scheme:     "pkg",
					Type:       purl.Type,
					Name:       purl.Name,
					Namespace:  &purl.Namespace,
					Qualifiers: &qualifiersStr,
					Subpath:    &purl.Subpath,
					Version:    &tmpV,

					CVE: cves,
				}
				affectedComponent.SetIdHash()
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		}
	}
	return affectedComponents
}
