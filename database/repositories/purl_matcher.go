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

package repositories

import (
	"regexp"
	"strings"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/lib/pq"
	"github.com/package-url/packageurl-go"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

// BuildQualifierQuery creates the database query for qualifier matching
func BuildQualifierQuery(db *gorm.DB, qualifiers packageurl.Qualifiers, namespace, version string) *gorm.DB {
	if patterns := QualifierEcosystemPattern(qualifiers, namespace, version); len(patterns) > 0 {
		return db.Where("ecosystem LIKE ANY (?)", pq.Array(patterns))
	}
	return db
}

// QualifierEcosystemPattern derives the `ecosystem LIKE ...` patterns implied by a
// purl's distro qualifier (any one of which matching is sufficient), or nil if the
// purl carries no usable distro. Purl qualifier keys are unique, so there is at
// most one distro to look at. The version is only consulted for Red Hat, whose
// release tells a RHEL build apart from a build of a layered product.
//
// BuildQualifierQuery turns the patterns into a where clause; the batched lookup
// in vulndb/scan instead groups purls by them, so that purls sharing a distro can
// be matched in one query.
func QualifierEcosystemPattern(qualifiers packageurl.Qualifiers, namespace, version string) []string {
	for _, qualifier := range qualifiers {
		if qualifier.Key != "distro" {
			continue
		}
		distro := qualifier.Value

		switch namespace {
		case "deb", "debian":
			// Capitalize the first letter of each word in the distro string (e.g., "debian-13.2" -> "Debian-13.2")
			distro = cases.Title(language.English).String(distro)
			// Parse distro string (e.g., "debian-13.2" -> "Debian:13")
			// Split by '-' to get distribution name and version
			parts := strings.Split(distro, "-")
			if len(parts) >= 2 {
				distroName := parts[0]
				majorVersion, _, _ := strings.Cut(parts[1], ".")    // Get major version (13.2 -> 13)
				ecosystemPattern := distroName + ":" + majorVersion // "Debian:13"

				return []string{ecosystemPattern + "%"}
			}
		case "apk", "alpine":
			// Only major and minor versions are used from the distro qualifier.
			// Example: "pkg:apk/alpine/curl@8.14.1-r2?arch=aarch64&distro=3.22.2" -> "Alpine:v3.22"
			parts := strings.Split(distro, ".")
			majorVersion := ""
			minorVersion := ""
			if len(parts) == 1 {
				// Alpine version only has major version
				majorVersion = parts[0] // Get major version (3 -> 3)
			} else if len(parts) >= 2 {
				majorVersion = parts[0] // Get major version (3.22.2 -> 3)
				minorVersion = parts[1] // Get minor version (3.22.2 -> 22)
			}
			ecosystemPattern := "Alpine:v" + majorVersion
			if minorVersion != "" {
				ecosystemPattern += "." + minorVersion
			}

			return []string{ecosystemPattern + "%"}
		case "redhat", "rhel", "centos":
			parts := strings.SplitN(distro, "-", 2)
			if len(parts) == 2 {
				majorVersion, _, _ := strings.Cut(parts[1], ".")
				if majorVersion != "" {
					return redHatEcosystemPatterns(majorVersion, version)
				}
			}
			return nil
		default:
			return nil
		}
	}

	return nil
}

// layeredProductRelease matches the release of an rpm built for a layered Red Hat
// product rather than for RHEL itself: the product appends its tag to the dist tag
// ("1.el9ap" for Ansible Automation Platform, "1.el9pc" and "1.el9sat" for
// Satellite, "1.el9ost" for OpenStack), or OpenShift prefixes its own
// ("6.rhaos4.14.el9"). RHEL builds end in a bare "elN", "elN_M" or a module tag
// ("275.el9_8", "1.module+el9.6.0+22647+1741ae35").
var layeredProductRelease = regexp.MustCompile(`el[0-9]+[a-z]|rhaos`)

// redHatEcosystemPatterns keeps an rpm purl to the advisories of its own product.
//
// Red Hat files the errata of its RHEL product lines under the RHEL major
// ("Red Hat:enterprise_linux:9::baseos", "Red Hat:rhel_eus:9.4::appstream",
// "Red Hat:enterprise_linux:10.2"), and those of layered products such as
// Satellite, Ansible Automation Platform or OpenShift under the product's own
// version with the major as an "elN" suffix ("Red Hat:satellite:6.16::el9",
// "Red Hat:enterprise_mrg:2:server:el6"). Layered products ship their own builds
// of RHEL packages, libcomps or python3-urllib3 for instance, with newer versions
// than RHEL does, so matching their errata against a RHEL build reports fixes
// that the RHEL repositories never carry.
//
// The purl names no product line, but the release does: a RHEL build is matched
// against the RHEL product lines only, a layered build against its own product
// as well. A product version that equals a RHEL major ("Red Hat:openstack:9::el7")
// no longer reaches into that major either.
//
// Example: "pkg:rpm/redhat/libcomps@0.1.18-1.el9?distro=redhat-9.8" ->
//
//	["Red Hat:enterprise_linux:9", "Red Hat:enterprise_linux:9::%",
//	 "Red Hat:enterprise_linux:9.%", "Red Hat:rhel_%:9", "Red Hat:rhel_%:9::%",
//	 "Red Hat:rhel_%:9.%"]
func redHatEcosystemPatterns(majorVersion, version string) []string {
	var patterns []string
	for _, productLine := range []string{"Red Hat:enterprise_linux:", "Red Hat:rhel_%:"} {
		patterns = append(patterns,
			productLine+majorVersion,
			productLine+majorVersion+"::%",
			productLine+majorVersion+".%",
		)
	}

	release := version[strings.LastIndex(version, "-")+1:]
	if layeredProductRelease.MatchString(release) {
		patterns = append(patterns, "Red Hat:%:el"+majorVersion)
	}
	return patterns
}

func BatchedVersionPredicates(interpretation normalize.VersionInterpretationType) []string {
	const exactVersion = `ac.version = ANY(ARRAY[q.version, q.original_version])`

	switch interpretation {
	case normalize.ExactVersionString:
		return []string{exactVersion}
	case normalize.EmptyVersion:
		return []string{`ac.version IS NULL AND ac.semver_introduced IS NULL AND ac.semver_fixed IS NULL AND ac.version_introduced IS NULL AND ac.version_fixed IS NULL`}
	case normalize.SemanticVersionString:
		return []string{
			exactVersion,
			// the semver ranges, minus anything the exact branch already returned.
			// q.semver is q.version encoded with normalize.SemverToBytes
			`((ac.semver_introduced IS NULL AND ac.semver_fixed > q.semver)
				OR (ac.semver_introduced <= q.semver AND ac.semver_fixed IS NULL)
				OR (ac.semver_introduced <= q.semver AND ac.semver_fixed > q.semver))
			AND ac.version IS DISTINCT FROM q.version AND ac.version IS DISTINCT FROM q.original_version`,
		}
	default:
		return []string{""}
	}
}
