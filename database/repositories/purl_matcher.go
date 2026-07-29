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
	"github.com/package-url/packageurl-go"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

// BuildQualifierQuery creates the database query for qualifier matching
func BuildQualifierQuery(db *gorm.DB, qualifiers packageurl.Qualifiers, namespace string) *gorm.DB {
	query := db
	for _, pattern := range QualifierEcosystemPatterns(qualifiers, namespace) {
		query = query.Where("ecosystem LIKE ?", pattern)
	}
	return query
}

// QualifierEcosystemPatterns derives the `ecosystem LIKE ...` patterns implied
// by a purl's distro qualifier. BuildQualifierQuery turns them into where
// clauses; the batched lookup in vulndb/scan instead groups purls by their
// pattern set, so that purls sharing a distro can be matched in one query.
func QualifierEcosystemPatterns(qualifiers packageurl.Qualifiers, namespace string) []string {
	var patterns []string

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

				patterns = append(patterns, ecosystemPattern+"%")
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

			patterns = append(patterns, ecosystemPattern+"%")
		default:
			return patterns
		}
	}

	return patterns
}

// BuildVersionRangeQuery creates the database query for version range matching
func buildVersionRangeQuery(db *gorm.DB, normalizedVersion string) *gorm.DB {
	// Use GORM's group conditions to properly wrap OR clauses
	return db.Where(
		db.Session(&gorm.Session{NewDB: true}).Where("version = ?", normalizedVersion).
			Or("semver_introduced IS NULL AND semver_fixed > ?", normalizedVersion).
			Or("semver_introduced <= ? AND semver_fixed IS NULL", normalizedVersion).
			Or("semver_introduced <= ? AND semver_fixed > ?", normalizedVersion, normalizedVersion),
	)
}

func buildEmptyVersionQuery(db *gorm.DB) *gorm.DB {
	return db.Where(
		db.Session(&gorm.Session{NewDB: true}).Where("version IS NULL AND semver_introduced IS NULL AND semver_fixed IS NULL AND version_introduced IS NULL AND version_fixed IS NULL"),
	)
}

// BatchedVersionPredicate is the batched counterpart of
// BuildQueryBasedOnMatchContext: instead of binding a single version as a
// parameter, it compares each affected_components row against a version coming
// from a joined relation, so many purls can be matched in one round trip.
//
// The returned SQL references the affected components as "ac" and the joined
// candidates as "q" (with a text column "version"). An empty string means the
// mode carries no SQL-expressible version predicate: EcosystemSpecificVersion
// has to be narrowed in Go by the caller.
//
// Keep this in sync with BuildQueryBasedOnMatchContext.
func BatchedVersionPredicate(interpretation normalize.VersionInterpretationType) string {
	switch interpretation {
	case normalize.ExactVersionString:
		return `ac.version = q.version`
	case normalize.EmptyVersion:
		return `ac.version IS NULL AND ac.semver_introduced IS NULL AND ac.semver_fixed IS NULL AND ac.version_introduced IS NULL AND ac.version_fixed IS NULL`
	case normalize.SemanticVersionString:
		return `(ac.version = q.version
			OR (ac.semver_introduced IS NULL AND ac.semver_fixed > q.version::semver)
			OR (ac.semver_introduced <= q.version::semver AND ac.semver_fixed IS NULL)
			OR (ac.semver_introduced <= q.version::semver AND ac.semver_fixed > q.version::semver))`
	default:
		return ""
	}
}

func BuildQueryBasedOnMatchContext(db *gorm.DB, ctx *normalize.PurlMatchContext) *gorm.DB {
	query := db

	switch ctx.HowToInterpretVersionString {
	case normalize.ExactVersionString:
		// Version is to be interpreted as exact string match only
		query = query.Where("version = ?", ctx.NormalizedVersion)
	case normalize.EmptyVersion:
		// Version is empty, match only entries with no version info
		query = buildEmptyVersionQuery(query)
	case normalize.EcosystemSpecificVersion:
		// Version is to be interpreted based on ecosystem-specific rules
		// those rules CAN ONLY BE expressed in Golang code, not in SQL
	case normalize.SemanticVersionString:
		// Version is to be interpreted as semantic versioning range
		query = buildVersionRangeQuery(query, ctx.NormalizedVersion)
	}

	return query
}
