// Copyright (C) 2026 l3montree GmbH
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
package dependencyfirewall

import (
	"log/slog"

	"github.com/blang/semver"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
)

// ecosystem abstracts the per-protocol behavior needed by the shared proxy logic.
type ecosystem interface {
	// name returns the identifier used in log fields and cache subdirectories.
	name() string
	// trimPrefix strips the /api/v1/dependency-proxy/[secret/]<ecosystem> prefix.
	trimPrefix(path string) string
	// parsePackage extracts the package name and version from the cleaned request path.
	parsePackage(path string) (packageName, version string)
	// packageIdentifier builds the string that firewall rules are matched against.
	// Most ecosystems use PURL format (pkg:<eco>/<name>@<version>).
	// OCI uses plain image reference format (registry/image:tag).
	packageIdentifier(packageName, version string) string
	// writeResponse writes the proxied payload to the HTTP response.
	writeResponse(c shared.Context, data []byte, path string, cached bool) error
	MatchesVersion(comp models.MaliciousAffectedComponent, version string) bool
}

// this is a function for basic version comparison, it does not handle semver ranges or complex versioning schemes. It is used for simple equality checks.
// but it might not be sufficient for all ecosystems. Therefore make sure to know what you are doing before using this function.
func semverMatchesVersion(comp models.MaliciousAffectedComponent, version string) bool {
	if comp.AffectsAllVersions() {
		// if all version information are nil
		return true
	}

	if comp.Version != nil {
		if *comp.Version == version {
			return true
		}
		// An unparsable requested version means we cannot rule out a match, so
		// assume it is affected to be safe (mirrors the range branch below).
		// An empty version is handled by the caller (checkMalicious defers the
		// decision until a version is resolved, unless AffectsAllVersions), so
		// it is not special-cased here.
		requested, err := normalize.ConvertToSemver(version)
		if err != nil {
			return true
		}
		stored, err := normalize.ConvertToSemver(*comp.Version)
		if err != nil {
			return true
		}
		// A version list entry carries no range, so this is the final answer.
		return stored == requested
	}

	v, err := parseSemver(version)
	if err != nil {
		slog.Debug("could not parse version for malicious range match", "version", version, "error", err)
		return true // if we cannot parse the version, we assume it is affected to be safe
	}

	if comp.SemverIntroduced != nil {
		introduced, err := semver.ParseTolerant(*comp.SemverIntroduced)
		if err != nil {
			return true // if we cannot parse the introduced version, we assume it is affected to be safe
		}
		if v.LT(introduced) {
			return false
		}
	}

	if comp.SemverFixed != nil {
		fixed, err := semver.ParseTolerant(*comp.SemverFixed)
		if err != nil {
			return true // if we cannot parse the fixed version, we assume it is affected to be safe
		}
		if v.GTE(fixed) {
			return false
		}
	}

	return true
}

func parseSemver(version string) (semver.Version, error) {
	normalized, err := normalize.ConvertToSemver(version)
	if err != nil {
		return semver.Version{}, err
	}
	return semver.ParseTolerant(normalized)
}

func EcosystemFromString(eco string) ecosystem {
	switch eco {
	case "npm":
		return npmEcosystem{}
	case "pypi":
		return pypiEcosystem{}
	case "golang":
		return goEcosystem{}
	case "oci":
		return ociEcosystem{}
	case "deb":
		return debEcosystem{}
	default:
		return nil
	}
}
