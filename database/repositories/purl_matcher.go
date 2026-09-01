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
	"strings"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/lib/pq"
	"github.com/package-url/packageurl-go"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

// BuildQualifierQuery creates the database query for qualifier matching
func BuildQualifierQuery(db *gorm.DB, qualifiers packageurl.Qualifiers, namespace string) *gorm.DB {
	if patterns := QualifierEcosystemPattern(qualifiers, namespace); len(patterns) > 0 {
		return db.Where("ecosystem LIKE ANY (?)", pq.Array(patterns))
	}
	return db
}

// QualifierEcosystemPattern derives the `ecosystem LIKE ...` patterns implied by a
// purl's distro qualifier (any one of which matching is sufficient), or nil if the
// purl carries no usable distro. Purl qualifier keys are unique, so there is at
// most one distro to look at.
//
// BuildQualifierQuery turns the patterns into a where clause; the batched lookup
// in vulndb/scan instead groups purls by them, so that purls sharing a distro can
// be matched in one query.
func QualifierEcosystemPattern(qualifiers packageurl.Qualifiers, namespace string) []string {
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
			// Only the major version is usable: Red Hat advisories are split across many
			// product lines (enterprise_linux, rhel_eus, rhel_aus, openshift, jboss, ...)
			// for the same major version, and the purl carries no qualifier that
			// identifies the product line (confirmed against the rpm purl-spec
			// definition, which only defines "arch" and "epoch" besides the de facto
			// "distro"). So we can't reproduce the exact product line here - just
			// exclude other majors and downstream distros (EulerOS, Red Hat Hardened
			// Images/hummingbird, ...).
			//
			// The major version shows up in the ecosystem string in two shapes:
			//   - directly after a colon, e.g. "Red Hat:enterprise_linux:9::baseos"
			//     or "Red Hat:rhel_eus:9.4::baseos"
			//   - as an "elN" suffix on add-on products, e.g.
			//     "Red Hat:jboss_core_services:1::el8" or "Red Hat:openstack:18.0::el9"
			// Example: "pkg:rpm/redhat/glibc@2.34-275.el9_8?distro=redhat-9.8" ->
			//   ["Red Hat:%:9%", "Red Hat:%el9%"]
			parts := strings.SplitN(distro, "-", 2)
			if len(parts) == 2 {
				majorVersion, _, _ := strings.Cut(parts[1], ".")
				if majorVersion != "" {
					return []string{
						"Red Hat:%:" + majorVersion + "%",
						"Red Hat:%el" + majorVersion + "%",
					}
				}
			}
			return nil
		default:
			return nil
		}
	}

	return nil
}

// The returned SQL references the affected components as "ac" and the joined
// candidates as "q" (with a text column "version"). An empty string means the
// mode carries no SQL-expressible version predicate: EcosystemSpecificVersion
// has to be narrowed in Go by the caller.
func BatchedVersionPredicate(interpretation normalize.VersionInterpretationType) string {
	switch interpretation {
	case normalize.ExactVersionString:
		return `(ac.version = q.version OR ac.version = q.original_version)`
	case normalize.EmptyVersion:
		return `ac.version IS NULL AND ac.semver_introduced IS NULL AND ac.semver_fixed IS NULL AND ac.version_introduced IS NULL AND ac.version_fixed IS NULL`
	case normalize.SemanticVersionString:
		return `(ac.version = q.version OR ac.version = q.original_version
			OR (ac.semver_introduced IS NULL AND ac.semver_fixed > q.version::semver)
			OR (ac.semver_introduced <= q.version::semver AND ac.semver_fixed IS NULL)
			OR (ac.semver_introduced <= q.version::semver AND ac.semver_fixed > q.version::semver))`
	default:
		return ""
	}
}
