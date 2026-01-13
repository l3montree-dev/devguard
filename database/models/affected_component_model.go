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
	"log/slog"
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"

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

	CVE []CVE `json:"cves" gorm:"many2many:cve_affected_component;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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

func AffectedComponentFromOSV(osv dtos.OSV) []AffectedComponent {
	affectedComponents := make([]AffectedComponent, 0)

	cveIds := osv.GetCVE()
	cves := make([]CVE, len(cveIds))
	for i, cveID := range cveIds {
		cves[i] = CVE{CVE: cveID}
	}

	for _, affected := range osv.Affected {
		// check if the affected package has a purl
		if affected.EcosystemSpecific != nil {
			// get the urgency - debian defines it: https://security-team.debian.org/security_tracker.html#severity-levels
			if affected.EcosystemSpecific.Urgency == "unimportant" {
				// just continue
				continue
			}
		}

		if affected.Package.Purl != "" {
			// Use the shared helper function with ecosystem conversion enabled
			bases := affectedComponentBaseFromAffected(affected)
			for _, base := range bases {
				affectedComponent := AffectedComponent{
					ID:                 "",
					Source:             "osv",
					PurlWithoutVersion: base.PurlWithoutVersion,
					Ecosystem:          base.Ecosystem,
					Scheme:             base.Scheme,
					Type:               base.Type,
					Name:               base.Name,
					Namespace:          base.Namespace,
					Qualifiers:         base.Qualifiers,
					Subpath:            base.Subpath,
					Version:            base.Version,
					SemverIntroduced:   base.SemverIntroduced,
					SemverFixed:        base.SemverFixed,
					VersionIntroduced:  base.VersionIntroduced,
					VersionFixed:       base.VersionFixed,
					CVE:                cves,
				}
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		} else {
			// Handle GIT ranges (no purl case)
			bases := affectedComponentBaseFromGitRange(affected)
			for _, base := range bases {
				affectedComponent := AffectedComponent{
					ID:                 "",
					Source:             "osv",
					PurlWithoutVersion: base.PurlWithoutVersion,
					Ecosystem:          base.Ecosystem,
					Scheme:             base.Scheme,
					Type:               base.Type,
					Name:               base.Name,
					Version:            base.Version,
					Namespace:          base.Namespace,
					SemverIntroduced:   base.SemverIntroduced,
					SemverFixed:        base.SemverFixed,
					VersionIntroduced:  base.VersionIntroduced,
					VersionFixed:       base.VersionFixed,
					CVE:                cves,
				}
				affectedComponents = append(affectedComponents, affectedComponent)
			}
		}
	}
	return affectedComponents
}

// affectedComponentBaseFromAffected extracts common base component data from an OSV affected entry.
// This helper is shared between malicious package and CVE processing; callers handle any ecosystem
// conversion (e.g., for Red Hat, Debian, Alpine) before invoking it.
func affectedComponentBaseFromAffected(affected dtos.Affected) []AffectedComponentBase {
	purlStr := affected.Package.Purl

	// If no purl provided, construct it from ecosystem and name
	if purlStr == "" {
		if affected.Package.Ecosystem == "" || affected.Package.Name == "" {
			return nil
		}

		// Map ecosystem to purl type
		ecosystemToPurlType := map[string]string{
			"npm":       "npm",
			"PyPI":      "pypi",
			"RubyGems":  "gem",
			"crates.io": "cargo",
			"Go":        "golang",
			"Packagist": "composer",
			"NuGet":     "nuget",
			"Hex":       "hex",
		}

		purlType, ok := ecosystemToPurlType[affected.Package.Ecosystem]
		if !ok {
			// Try lowercase version
			purlType = strings.ToLower(affected.Package.Ecosystem)
		}

		purlStr = fmt.Sprintf("pkg:%s/%s", purlType, affected.Package.Name)
	}

	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return nil
	}

	qualifiersStr := purl.Qualifiers.String()
	purlWithoutVersion := strings.Split(purlStr, "?")[0]

	// Try processing ranges first
	bases := processRanges(affected.Ranges, affected.Package.Ecosystem, purlWithoutVersion, purl, qualifiersStr)

	// If no ranges produced results, fall back to explicit versions
	if len(bases) == 0 && len(affected.Versions) > 0 {
		bases = processVersions(affected.Versions, affected.Package.Ecosystem, purlWithoutVersion, purl, qualifiersStr)
	}

	// If still nothing, all versions are affected
	if len(bases) == 0 {
		bases = []AffectedComponentBase{createBase(purlWithoutVersion, affected.Package.Ecosystem, purl, qualifiersStr, nil, nil, nil, nil, nil)}
	}

	return bases
}

func processRanges(ranges []dtos.Rng, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0)

	for _, r := range ranges {
		if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
			// Try to process all ECOSYSTEM ranges - conversion will fail naturally if not compatible
			bases = append(bases, processRange(r, ecosystem, purlWithoutVersion, purl, qualifiersStr)...)
		}
	}

	return bases
}

func processRange(r dtos.Rng, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0)

	for i := 0; i < len(r.Events); i += 2 {
		introduced := r.Events[i].Introduced
		fixed := ""
		if i+1 < len(r.Events) {
			fixed = r.Events[i+1].Fixed
		}

		var semverIntroduced, semverFixed, versionIntroduced, versionFixed *string

		if purl.Type == "deb" || purl.Type == "rpm" || purl.Type == "apk" {
			versionIntroduced = &introduced
			if fixed != "" {
				versionFixed = &fixed
			}
		} else {
			semverInt, err := normalize.ConvertToSemver(introduced)
			semverIntroduced = &semverInt
			if err != nil {
				continue
			}

			if fixed != "" {
				converted, err := normalize.ConvertToSemver(fixed)
				if err != nil {
					continue
				}
				semverFixed = &converted
			}
		}

		bases = append(bases, createBase(purlWithoutVersion, ecosystem, purl, qualifiersStr, semverIntroduced, semverFixed, versionIntroduced, versionFixed, nil))
	}

	return bases
}

func processVersions(versions []string, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0, len(versions))

	for _, v := range versions {
		version := v
		bases = append(bases, createBase(purlWithoutVersion, ecosystem, purl, qualifiersStr, nil, nil, nil, nil, &version))
	}

	return bases
}

func createBase(purlWithoutVersion, ecosystem string, purl packageurl.PackageURL, qualifiersStr string, semverIntroduced, semverFixed, versionIntroduced, versionFixed, version *string) AffectedComponentBase {
	return AffectedComponentBase{
		PurlWithoutVersion: purlWithoutVersion,
		Ecosystem:          ecosystem,
		Scheme:             "pkg",
		Type:               purl.Type,
		Name:               purl.Name,
		Namespace:          &purl.Namespace,
		Qualifiers:         &qualifiersStr,
		Subpath:            &purl.Subpath,
		SemverIntroduced:   semverIntroduced,
		SemverFixed:        semverFixed,
		Version:            version,
		VersionIntroduced:  versionIntroduced,
		VersionFixed:       versionFixed,
	}
}

// affectedComponentBaseFromGitRange extracts base component data from GIT ranges (used for CVEs)
func affectedComponentBaseFromGitRange(affected dtos.Affected) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0)

	for _, r := range affected.Ranges {
		if r.Type != "GIT" {
			continue
		}

		// parse the repo as url
		url, err := url.Parse(r.Repo)
		if err != nil {
			slog.Debug("could not parse repo url", "url", r.Repo, "err", err)
			continue
		}

		if url.Host != "github.com" && url.Host != "gitlab.com" && url.Host != "bitbucket.org" {
			// we currently dont support those.
			continue
		}
		// remove the scheme
		url.Scheme = ""
		purl := fmt.Sprintf("pkg:%s", url.Host+strings.TrimSuffix(url.Path, ".git"))

		// parse the purl to get the name and namespace
		purlParsed, err := packageurl.FromString(purl)
		if err != nil {
			slog.Debug("could not parse purl", "purl", purl, "err", err)
			continue
		}

		for _, v := range affected.Versions {
			tmpV := v
			base := AffectedComponentBase{
				PurlWithoutVersion: purl,
				Ecosystem:          "GIT",
				Scheme:             "pkg",
				Type:               purlParsed.Type,
				Name:               purlParsed.Name,
				Version:            &tmpV,
				Namespace:          &purlParsed.Namespace,
			}
			bases = append(bases, base)
		}
	}

	return bases
}
