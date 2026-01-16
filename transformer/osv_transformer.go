package transformer

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
)

// need Optimus Prime here
func OSVToCVERelationships(osv *dtos.OSV) []models.CVERelationship {
	relations := make([]models.CVERelationship, 0)
	for _, alias := range osv.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			relations = append(relations, models.CVERelationship{
				SourceCVE:        osv.ID,
				TargetCVE:        alias,
				RelationshipType: dtos.RelationshipTypeAlias,
			})
		}
	}

	for _, upstream := range osv.Upstream {
		if strings.HasPrefix(upstream, "CVE-") {
			relations = append(relations, models.CVERelationship{
				SourceCVE:        osv.ID,
				TargetCVE:        upstream,
				RelationshipType: dtos.RelationshipTypeUpstream,
			})
		}
	}

	// check if its related to a cve
	for _, related := range osv.Related {
		if strings.HasPrefix(related, "CVE-") {
			relations = append(relations, models.CVERelationship{
				SourceCVE:        osv.ID,
				TargetCVE:        related,
				RelationshipType: dtos.RelationshipTypeRelated,
			})
		}
	}
	return relations
}

func AffectedComponentsFromOSV(osv *dtos.OSV) []models.AffectedComponent {
	if osv == nil {
		return []models.AffectedComponent{}
	}
	affectedComponents := make([]models.AffectedComponent, 0, len(osv.Affected))

	cveRelations := OSVToCVERelationships(osv)
	cves := make([]models.CVE, len(cveRelations))
	for i, relation := range cveRelations {
		cves[i] = models.CVE{CVE: relation.TargetCVE}
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
				affectedComponent := models.AffectedComponent{
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
				affectedComponent := models.AffectedComponent{
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
func affectedComponentBaseFromAffected(affected dtos.Affected) []models.AffectedComponentBase {
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

	// Try processing ranges first
	bases := processRanges(affected.Ranges, affected.Package.Ecosystem, purl)

	// If no ranges produced results, fall back to explicit versions
	if len(bases) == 0 && len(affected.Versions) > 0 {
		bases = processVersions(affected.Versions, affected.Package.Ecosystem, purl)
	}

	// If still nothing, all versions are affected
	if len(bases) == 0 {
		bases = []models.AffectedComponentBase{createBase(affected.Package.Ecosystem, purl, nil, nil, nil, nil, nil)}
	}

	return bases
}

func processRanges(ranges []dtos.Range, ecosystem string, purl packageurl.PackageURL) []models.AffectedComponentBase {
	bases := make([]models.AffectedComponentBase, 0)

	for _, r := range ranges {
		if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
			// Try to process all ECOSYSTEM ranges - conversion will fail naturally if not compatible
			bases = append(bases, processRange(r, ecosystem, purl)...)
		}
	}

	return bases
}

func processRange(r dtos.Range, ecosystem string, purl packageurl.PackageURL) []models.AffectedComponentBase {
	bases := make([]models.AffectedComponentBase, 0)

	for i := 0; i < len(r.Events); i += 2 {
		introduced := r.Events[i].Introduced
		fixed := ""
		if i+1 < len(r.Events) {
			fixed = r.Events[i+1].Fixed
		}

		// versionIntroduced and semverIntroduced should be nil if introduced is "0"
		var semverIntroduced, semverFixed, versionIntroduced, versionFixed *string
		if purl.Type == "deb" || purl.Type == "rpm" || purl.Type == "apk" {
			if introduced != "0" && introduced != "" {
				versionIntroduced = &introduced
			}

			if fixed != "" {
				versionFixed = &fixed
			}
		} else {
			if introduced != "0" && introduced != "" {
				semverInt, err := normalize.ConvertToSemver(introduced)
				if err != nil {
					continue
				}
				semverIntroduced = &semverInt
			}

			if fixed != "" {
				converted, err := normalize.ConvertToSemver(fixed)
				if err != nil {
					continue
				}
				semverFixed = &converted
			}
		}

		bases = append(bases, createBase(ecosystem, purl, semverIntroduced, semverFixed, nil, versionIntroduced, versionFixed))
	}

	return bases
}

func processVersions(versions []string, ecosystem string, purl packageurl.PackageURL) []models.AffectedComponentBase {
	bases := make([]models.AffectedComponentBase, 0, len(versions))

	for _, v := range versions {
		version := v
		bases = append(bases, createBase(ecosystem, purl, nil, nil, &version, nil, nil))
	}

	return bases
}

func createBase(ecosystem string, purl packageurl.PackageURL, semverIntroduced, semverFixed, version, versionIntroduced, versionFixed *string) models.AffectedComponentBase {
	return models.AffectedComponentBase{
		PurlWithoutVersion: normalize.ToPurlWithoutVersion(purl),
		Ecosystem:          ecosystem,
		Scheme:             "pkg",
		Type:               purl.Type,
		Name:               purl.Name,
		Namespace:          &purl.Namespace,
		Qualifiers:         databasetypes.MustJSONBFromStruct(purl.Qualifiers.Map()),
		Subpath:            &purl.Subpath,
		SemverIntroduced:   semverIntroduced,
		SemverFixed:        semverFixed,
		Version:            version,
		VersionIntroduced:  versionIntroduced,
		VersionFixed:       versionFixed,
	}
}

// affectedComponentBaseFromGitRange extracts base component data from GIT ranges (used for CVEs)
func affectedComponentBaseFromGitRange(affected dtos.Affected) []models.AffectedComponentBase {
	bases := make([]models.AffectedComponentBase, 0)

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
			base := models.AffectedComponentBase{
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

// MaliciousAffectedComponentFromOSV converts OSV data to MaliciousAffectedComponent entries
func MaliciousAffectedComponentFromOSV(osv dtos.OSV, maliciousPackageID string) []models.MaliciousAffectedComponent {
	affectedComponents := make([]models.MaliciousAffectedComponent, 0)
	for _, affected := range osv.Affected {
		bases := affectedComponentBaseFromAffected(affected) // malicious packages don't need ecosystem conversion
		for _, base := range bases {
			affectedComponent := models.MaliciousAffectedComponent{
				MaliciousPackageID:    maliciousPackageID,
				AffectedComponentBase: base,
			}
			affectedComponents = append(affectedComponents, affectedComponent)
		}
	}

	return affectedComponents
}
