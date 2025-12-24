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

	"github.com/package-url/packageurl-go"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

// BuildQualifierQuery creates the database query for qualifier matching
func BuildQualifierQuery(db *gorm.DB, qualifiers packageurl.Qualifiers, namespace string) *gorm.DB {
	query := db

	for _, qualifier := range qualifiers {
		if qualifier.Key != "distro" {
			continue
		}
		distro := qualifier.Value

		switch namespace {
		case "debian":
			// Capitalize the first letter of each word in the distro string (e.g., "debian-13.2" -> "Debian-13.2")
			distro = cases.Title(language.English).String(distro)
			// Parse distro string (e.g., "debian-13.2" -> "Debian:13")
			// Split by '-' to get distribution name and version
			parts := strings.Split(distro, "-")
			if len(parts) >= 2 {
				distroName := parts[0]
				majorVersion := strings.Split(parts[1], ".")[0]     // Get major version (13.2 -> 13)
				ecosystemPattern := distroName + ":" + majorVersion // "Debian:13"

				query = query.Where("ecosystem LIKE ?", ecosystemPattern+"%")
			}
		case "alpine":
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

			query = query.Where("ecosystem LIKE ?", ecosystemPattern+"%")
		default:
			return query
		}
	}

	return query
}

// BuildVersionRangeQuery creates the database query for version range matching
func BuildVersionRangeQuery(db *gorm.DB, targetVersion, normalizedVersion string) *gorm.DB {
	// Use GORM's group conditions to properly wrap OR clauses
	return db.Where(
		db.Session(&gorm.Session{NewDB: true}).Where("version = ?", targetVersion).
			Or("semver_introduced IS NULL AND semver_fixed > ?", normalizedVersion).
			Or("semver_introduced <= ? AND semver_fixed IS NULL", normalizedVersion).
			Or("semver_introduced <= ? AND semver_fixed > ?", normalizedVersion, normalizedVersion),
	)
}
