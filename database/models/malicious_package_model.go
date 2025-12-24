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
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
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

// affectedComponentBaseFromAffected extracts common base component data from OSV affected entry
// Set convertEcosystem=true for CVE processing to handle Red Hat, Debian, Alpine ecosystems
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
		bases = []AffectedComponentBase{createBase(purlWithoutVersion, affected.Package.Ecosystem, purl, qualifiersStr, nil, nil, nil)}
	}

	return bases
}

func processRanges(ranges []dtos.Rng, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0)

	for _, r := range ranges {
		switch r.Type {
		case "SEMVER":
			bases = append(bases, processSemverRange(r, ecosystem, purlWithoutVersion, purl, qualifiersStr)...)
		case "ECOSYSTEM":
			// Try to process all ECOSYSTEM ranges - conversion will fail naturally if not compatible
			bases = append(bases, processEcosystemRange(r, ecosystem, purlWithoutVersion, purl, qualifiersStr)...)
		}
	}

	return bases
}

func processSemverRange(r dtos.Rng, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0)

	for i := 0; i < len(r.Events); i += 2 {
		introduced := r.Events[i].Introduced
		fixed := ""
		if i+1 < len(r.Events) {
			fixed = r.Events[i+1].Fixed
		}

		semverIntroduced, err := normalize.ConvertToSemver(introduced)
		if err != nil {
			continue
		}

		var semverFixed *string
		if fixed != "" {
			converted, err := normalize.ConvertToSemver(fixed)
			if err == nil {
				semverFixed = &converted
			}
		}

		bases = append(bases, createBase(purlWithoutVersion, ecosystem, purl, qualifiersStr, &semverIntroduced, semverFixed, nil))
	}

	return bases
}

func processEcosystemRange(r dtos.Rng, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0)

	for i := 0; i < len(r.Events); i += 2 {
		introduced := r.Events[i].Introduced
		fixed := ""
		if i+1 < len(r.Events) {
			fixed = r.Events[i+1].Fixed
		}

		semverIntroduced, err := normalize.ConvertToSemver(introduced)
		if err != nil {
			continue
		}

		var semverFixed *string
		if fixed != "" {
			converted, err := normalize.ConvertToSemver(fixed)
			if err == nil {
				semverFixed = &converted
			}
		}

		bases = append(bases, createBase(purlWithoutVersion, ecosystem, purl, qualifiersStr, &semverIntroduced, semverFixed, nil))
	}

	return bases
}

func processVersions(versions []string, ecosystem, purlWithoutVersion string, purl packageurl.PackageURL, qualifiersStr string) []AffectedComponentBase {
	bases := make([]AffectedComponentBase, 0, len(versions))

	for _, v := range versions {
		version := v
		bases = append(bases, createBase(purlWithoutVersion, ecosystem, purl, qualifiersStr, nil, nil, &version))
	}

	return bases
}

func createBase(purlWithoutVersion, ecosystem string, purl packageurl.PackageURL, qualifiersStr string, semverIntroduced, semverFixed, version *string) AffectedComponentBase {
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
	}
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
