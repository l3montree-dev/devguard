package transformer

import (
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/blang/semver"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
	"gorm.io/datatypes"
)

// redHatEcosystemHasRHELMajor matches Red Hat OSV ecosystem strings that carry a
// recognizable RHEL major version, either directly after a colon
// ("Red Hat:enterprise_linux:9::baseos", "Red Hat:rhel_eus:9.4::baseos") or as an
// "elN" suffix used by add-on products ("Red Hat:jboss_core_services:1::el8").
// repositories.QualifierEcosystemPattern can only ever narrow a purl's distro
// qualifier down to one of these two shapes, so an ecosystem matching neither
// (year-versioned products, legacy pre-RHEL-3 releases, standalone product lines
// like Red Hat Hardened Images/hummingbird, ...) can never be reached by a
// distro-qualified rpm lookup - keeping such rows around only wastes space.
var redHatEcosystemHasRHELMajor = regexp.MustCompile(`^Red Hat:.*(:|el)([3-9]|[1-9][0-9])([^0-9]|$)`)

func isUnmatchableRedHatEcosystem(ecosystem string) bool {
	return strings.HasPrefix(ecosystem, "Red Hat:") && !redHatEcosystemHasRHELMajor.MatchString(ecosystem)
}

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

func OSVToCVE(osv *dtos.OSV) models.CVE {
	cve := models.CVE{}
	cvssScore, cvssVector, ok := hasValidCVSSScore(osv)
	if ok {
		cve.CVSS = float32(cvssScore)
		cve.Vector = cvssVector
	} else {
		// if we cannot parse a CVSS score we save the CVE with a CVSS score of -1
		cve.CVSS = float32(-1)
	}

	cve.CVE = osv.ID
	cve.Description = osv.Details
	if cve.Description == "" {
		cve.Description = osv.Summary
	}

	cve.DatePublished = osv.Published
	cve.DateLastModified = osv.Modified
	cve.Withdrawn = (*datatypes.Date)(osv.Withdrawn)

	cwes := strings.Join(osv.DatabaseSpecific.CWEs, ",")
	if cwes != "" { // omit cve.cwes if osv.cwes is empty
		cve.CWEs = &cwes
	}

	return cve
}

// checks if a valid CVSS score is available, if so return the score as well as the corresponding vector
func hasValidCVSSScore(osv *dtos.OSV) (float64, string, bool) {
	for _, severity := range osv.Severity {
		// currently only supporting CVSS Version 3 and 4
		if strings.HasPrefix(severity.Score, "CVSS:3.1") {
			cvssScore, err := gocvss31.ParseVector(severity.Score)
			if err == nil {
				return cvssScore.BaseScore(), cvssScore.Vector(), true
			}
		} else if strings.HasPrefix(severity.Score, "CVSS:3.0") {
			cvssScore, err := gocvss30.ParseVector(severity.Score)
			if err == nil {
				return cvssScore.BaseScore(), cvssScore.Vector(), true
			}
		} else if strings.HasPrefix(severity.Score, "CVSS:4.0") {
			cvssScore, err := gocvss40.ParseVector(severity.Score)
			if err == nil {
				return cvssScore.Score(), cvssScore.Vector(), true
			}
		}
	}
	return 0, "", false
}

func AffectedComponentsFromOSV(osv *dtos.OSV) []models.AffectedComponent {
	if osv == nil {
		return []models.AffectedComponent{}
	}

	affectedComponents := make([]models.AffectedComponent, 0, len(osv.Affected)*3)

	for _, affected := range osv.Affected {
		// we should not remove affected components - otherwise it might happen, that we remove a vulnerability from the database (check runCleanupJobs) and therefore lose the append only property of this database - which makes it so fast and simple currently.
		/*if affected.EcosystemSpecific != nil {
			// debian defines urgency: https://security-team.debian.org/security_tracker.html#severity-levels
			affected.EcosystemSpecific.Urgency == "unimportant" {
				// continue
			}
		}*/

		// exception to the append-only rule above: these rows are dead on arrival,
		// not merely withdrawn - no rpm lookup can ever reach them, see
		// isUnmatchableRedHatEcosystem.
		if isUnmatchableRedHatEcosystem(affected.Package.Ecosystem) {
			continue
		}

		if affected.Package.Purl != "" {
			affectedComponents = append(affectedComponents, affectedComponentsFromAffected(affected)...)
		} else {
			affectedComponents = append(affectedComponents, affectedComponentsFromGitRange(affected)...)
		}
	}
	return affectedComponents
}

func affectedComponentsFromAffected(affected dtos.Affected) []models.AffectedComponent {
	purlStr := affected.Package.Purl

	if purlStr == "" {
		if affected.Package.Ecosystem == "" || affected.Package.Name == "" {
			return nil
		}

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
			purlType = strings.ToLower(affected.Package.Ecosystem)
		}

		purlStr = fmt.Sprintf("pkg:%s/%s", purlType, affected.Package.Name)
	}

	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return nil
	}

	components := processRanges(affected.Ranges, affected.Package.Ecosystem, purl)

	if len(components) == 0 && len(affected.Versions) > 0 {
		components = processVersions(affected.Versions, affected.Package.Ecosystem, purl)
	}

	if len(components) == 0 {
		components = []models.AffectedComponent{newAffectedComponent(affected.Package.Ecosystem, purl, nil, nil, nil, nil, nil)}
	}

	return components
}

func processRanges(ranges []dtos.Range, ecosystem string, purl packageurl.PackageURL) []models.AffectedComponent {
	upper := 0
	for _, r := range ranges {
		if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
			upper += len(r.Events)/2 + 1
		}
	}
	components := make([]models.AffectedComponent, 0, upper)

	for _, r := range ranges {
		if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
			components = append(components, processRange(r, ecosystem, purl)...)
		}
	}

	return components
}

func incrementPatchVersion(version string) (string, error) {
	v, err := semver.ParseTolerant(version)
	if err != nil {
		return "", err
	}
	v.Patch++
	return v.String(), nil
}

// ref: https://ossf.github.io/osv-schema/#requirements
func processRange(r dtos.Range, ecosystem string, purl packageurl.PackageURL) []models.AffectedComponent {
	components := make([]models.AffectedComponent, 0, len(r.Events))

	introduced := ""
	closed := true // no pending introduced event to close yet
	for _, event := range r.Events {
		if event.Introduced != "" {
			if !closed {
				// no closing event was found for the previous introduced — record it as open-ended
				component, _ := buildRangeComponent(ecosystem, purl, introduced, "")
				components = append(components, component)
			}
			introduced = event.Introduced
			closed = false
			continue
		}

		if closed {
			// extra fixed/last_affected events (e.g. cherrypicks on other branches) after
			// the range was already closed only record the first one as the end of the range
			continue
		}

		fixed := event.Fixed
		if fixed == "" && event.LastAffected != "" {
			incremented, err := incrementPatchVersion(event.LastAffected)
			if err != nil {
				// non-semver last_affected — skip this closing event entirely so the
				// versions slice fallback in affectedComponentsFromAffected takes over
				closed = true
				continue
			}
			fixed = incremented
		}

		component, ok := buildRangeComponent(ecosystem, purl, introduced, fixed)
		if !ok {
			// unparseable fixed version — skip this closing event entirely
			closed = true
			continue
		}
		components = append(components, component)
		closed = true
	}

	if !closed {
		// no closing event was found at all — record it as open-ended
		component, _ := buildRangeComponent(ecosystem, purl, introduced, "")
		components = append(components, component)
	}

	return components
}

// buildRangeComponent builds the component for an introduced/fixed pair. It returns
// ok=false when fixed is set but cannot be parsed, in which case the range should be
// dropped entirely by the caller.
func buildRangeComponent(ecosystem string, purl packageurl.PackageURL, introduced, fixed string) (models.AffectedComponent, bool) {
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
				return models.AffectedComponent{}, false
			}
			semverIntroduced = &semverInt
		}
		if fixed != "" {
			converted, err := normalize.ConvertToSemver(fixed)
			if err != nil {
				return models.AffectedComponent{}, false
			}
			semverFixed = &converted
		}
	}

	return newAffectedComponent(ecosystem, purl, semverIntroduced, semverFixed, nil, versionIntroduced, versionFixed), true
}

func processVersions(versions []string, ecosystem string, purl packageurl.PackageURL) []models.AffectedComponent {
	components := make([]models.AffectedComponent, 0, len(versions))
	for i := range versions {
		components = append(components, newAffectedComponent(ecosystem, purl, nil, nil, &versions[i], nil, nil))
	}
	return components
}

func newAffectedComponent(ecosystem string, purl packageurl.PackageURL, semverIntroduced, semverFixed, version, versionIntroduced, versionFixed *string) models.AffectedComponent {
	return models.AffectedComponent{
		PurlWithoutVersion: normalize.ToPurlWithoutVersion(purl),
		Ecosystem:          ecosystem,
		SemverIntroduced:   semverIntroduced,
		SemverFixed:        semverFixed,
		Version:            version,
		VersionIntroduced:  versionIntroduced,
		VersionFixed:       versionFixed,
	}
}

func affectedComponentsFromGitRange(affected dtos.Affected) []models.AffectedComponent {
	upper := 0
	for _, r := range affected.Ranges {
		if r.Type == "GIT" {
			upper += len(affected.Versions)
		}
	}
	components := make([]models.AffectedComponent, 0, upper)

	for _, r := range affected.Ranges {
		if r.Type != "GIT" {
			continue
		}

		u, err := url.Parse(r.Repo)
		if err != nil {
			slog.Debug("could not parse repo url", "url", r.Repo, "err", err)
			continue
		}

		if u.Host != "github.com" && u.Host != "gitlab.com" && u.Host != "bitbucket.org" {
			continue
		}
		u.Scheme = ""
		purl := fmt.Sprintf("pkg:%s", u.Host+strings.TrimSuffix(u.Path, ".git"))

		for i := range affected.Versions {
			components = append(components, models.AffectedComponent{
				PurlWithoutVersion: purl,
				Ecosystem:          "GIT",
				Version:            &affected.Versions[i],
			})
		}
	}

	return components
}

// MaliciousAffectedComponentFromOSV converts OSV data to MaliciousAffectedComponent entries
func MaliciousAffectedComponentFromOSV(osv *dtos.OSV, maliciousPackageID string) []models.MaliciousAffectedComponent {
	affectedComponents := make([]models.MaliciousAffectedComponent, 0)
	for _, affected := range osv.Affected {
		for _, c := range affectedComponentsFromAffected(affected) {
			m := models.MaliciousAffectedComponent{
				MaliciousPackageID: maliciousPackageID,
				PurlWithoutVersion: c.PurlWithoutVersion,
				Ecosystem:          c.Ecosystem,
				Version:            c.Version,
				SemverIntroduced:   c.SemverIntroduced,
				SemverFixed:        c.SemverFixed,
				VersionIntroduced:  c.VersionIntroduced,
				VersionFixed:       c.VersionFixed,
			}
			m.ID = m.CalculateHash()
			affectedComponents = append(affectedComponents, m)
		}
	}
	return affectedComponents
}
