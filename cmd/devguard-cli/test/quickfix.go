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
package main

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/semver"
)

func mapPackageManagerToEcosystem(pkg string) string {
	// insert future Package Managers later
	switch pkg {

	case "npm", "yarn", "pnpm":
		return "node"

	case "pip", "pipenv", "poetry":
		return "python"

	case "cargo":
		return "crates"

	case "deb", "debian":
		return "deb"
	}

	return "unknown"
}

func parseVersion(version string) [3]int {
	var result [3]int

	// Skip parsing if version is empty
	if version == "" {
		return [3]int{0, 0, 0}
	}

	cleanVersion := version
	if idx := strings.IndexAny(version, "-+"); idx != -1 {
		cleanVersion = version[:idx]
	}

	// Attempt to parse; silently return [0, 0, 0] on failure since all
	// callers should have already validated with semver.IsValid()
	fmt.Sscanf(cleanVersion, "%d.%d.%d", &result[0], &result[1], &result[2])
	return result
}

func parsePurl(purl string) (pkgType string, name string, version string, err error) {
	// Format: pkg:npm/package-name@version, pkg:cargo/crate@version, etc.
	// Note: version can be empty string to indicate "all versions" (see RegistryRequest)
	input, err := packageurl.FromString(purl)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid purl format: %w", err)
	}

	pkgName := input.Name
	if input.Namespace != "" {
		pkgName = input.Namespace + "/" + input.Name
	}
	pkgVersion := strings.TrimSpace(input.Version)

	return input.Type, pkgName, pkgVersion, nil
}

func splitOrExpression(versionConstraint string) []string {
	parts := strings.Split(versionConstraint, "||")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func matchesVersionConstraint(rangeType string, version string, versionParts [3]int, baseVersion string, baseParts [3]int) bool {
	switch rangeType {
	case "^":
		// ^0.2.3 resolves to <0.3.0 not <0.99.0
		if baseParts[0] > 0 {
			return versionParts[0] == baseParts[0] && semver.Compare("v"+version, "v"+baseVersion) >= 0
		} else if baseParts[1] > 0 {
			return versionParts[0] == 0 && versionParts[1] == baseParts[1] && semver.Compare("v"+version, "v"+baseVersion) >= 0
		} else {
			return versionParts[0] == 0 && versionParts[1] == 0 && versionParts[2] == baseParts[2] && semver.Compare("v"+version, "v"+baseVersion) >= 0
		}

	case "~":
		// Tilde: same major.minor, >= patch
		return versionParts[0] == baseParts[0] && versionParts[1] == baseParts[1] && semver.Compare("v"+version, "v"+baseVersion) >= 0

	case ">=":
		// Greater than or equal: same major version, >= base
		return versionParts[0] == baseParts[0] && semver.Compare("v"+version, "v"+baseVersion) >= 0

	case ">":
		// Greater than: same major version, > base
		return versionParts[0] == baseParts[0] && semver.Compare("v"+version, "v"+baseVersion) > 0

	case "exact":
		// Exact version match
		return version == baseVersion

	default:
		return false
	}
}

// Examples: "14" -> "14.0.0", "14.0" -> "14.0.0", "14.0.0" -> "14.0.0"
func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)

	// Strip pre-release and build metadata first
	if idx := strings.IndexAny(version, "-+"); idx != -1 {
		version = version[:idx]
	}

	parts := strings.Split(version, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return strings.Join(parts, ".")
}

// parseVersionConstraint extracts the range type and base version from a version spec
// Returns the range type ("^", "~", ">=", ">", "exact") and the trimmed base version
// Pre-release versions are stripped (e.g., "15.0.0-rc.0" becomes "15.0.0")
func parseVersionConstraint(spec string) (rangeType string, baseVersion string) {
	spec = strings.TrimSpace(spec)

	// Extract base version (without range prefix)
	var extracted string
	if strings.HasPrefix(spec, "^") {
		rangeType = "^"
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, "^"))
	} else if strings.HasPrefix(spec, "~") {
		rangeType = "~"
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, "~"))
	} else if strings.HasPrefix(spec, ">=") {
		rangeType = ">="
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, ">="))
	} else if strings.HasPrefix(spec, ">") {
		rangeType = ">"
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, ">"))
	} else {
		// Exact version (no prefix)
		rangeType = "exact"
		extracted = spec
	}

	// Strip pre-release and build metadata (e.g., "15.0.0-rc.0" -> "15.0.0")
	if idx := strings.IndexAny(extracted, "-+"); idx != -1 {
		extracted = extracted[:idx]
	}

	return rangeType, extracted
}

// resolveBestVersion finds the best matching version given a version spec and all available versions
// versionConstraint examples: "15.4.7", "^15.0.0", "~15.4.0", ">15.0.0", ">=15.4.0"
// Also supports incomplete semver like "^14.0", "^14", "~15", etc.
// Returns the highest matching version, or error if no match or spec is invalid
type VersionConstraint string

type Resolver[T any] interface {
	FetchPackageMetadata(purl packageurl.PackageURL) (T, error)
	GetRecommendedVersions(allVersionsMeta T, currentVersion string) ([]string, error)
	// imagine A --> B
	// FindDependencyVersionInMeta looks into A's metadata and finds the version spec for B (e.g., ^15.0.0, ~15.4.0, >15.0.0, >=15.4.0, etc.) - But not necessarily an exact version, it could also be a range or constraint
	FindDependencyVersionInMeta(depMeta T, pkgName string) VersionConstraint
	ResolveBestVersion(allVersionsMeta T, versionConstraint VersionConstraint, currentVersion string) (string, error)
	CheckIfVulnerabilityIsFixed(vulnVersion string, fixedVersion string) bool
}

func checkVulnerabilityFixChain[T any](resolver Resolver[T], purls []packageurl.PackageURL, fixedVersion string) (string, error) {

	if len(purls) < 2 {
		return "", fmt.Errorf("purl array must contain at least 2 elements")
	}

	// Version format validation is delegated to each resolver
	// (semver for NPM, Debian version for Debian packages)

	for i := 0; i < len(purls)-1; i++ {
		pkgName := purls[i].Name
		currentVersion := purls[i].Version

		// fetch all version
		allVersionsMeta, err := resolver.FetchPackageMetadata(purls[i])
		if err != nil {
			return "", fmt.Errorf("failed to fetch all versions for %s: %w", pkgName, err)
		}

		var latestVersion string
		if i == 0 {
			versions, err := resolver.GetRecommendedVersions(allVersionsMeta, currentVersion)
			if err != nil {
				return "", fmt.Errorf("failed to get recommended versions for %s: %w", pkgName, err)
			}

			if len(versions) == 0 {
				return "", fmt.Errorf("no newer version available for %s@%s in the same major band", pkgName, currentVersion)
			}

			latestVersion = versions[0]
			if latestVersion == currentVersion {
				return "", fmt.Errorf("no new version available for %s (current: %s)", pkgName, currentVersion)
			}
		} else {
			// we are not resolving any ^ or ~, therefore we are only allowed to use the EXACT version specified in the previous package's dependencies
			latestVersion = currentVersion
		}
		purls[i].Version = latestVersion
		fmt.Printf("Found newer version for %s: %s to %s\n", pkgName, currentVersion, latestVersion)

		// Second: check latest version
		latestMeta, err := resolver.FetchPackageMetadata(purls[i])
		if err != nil {
			return "", fmt.Errorf("failed to fetch latest metadata for %s@%s: %w", pkgName, latestVersion, err)
		}

		nextPkgName := purls[i+1].Name

		// next version spec might not be an exact version, but could also be a range like ^15.0.0, ~15.4.0, >15.0.0, >=15.4.0, etc.
		nextVersionConstraint := resolver.FindDependencyVersionInMeta(latestMeta, nextPkgName)
		if nextVersionConstraint == "" {
			return "", fmt.Errorf("package %s not found in %s@%s dependencies", nextPkgName, pkgName, latestVersion)
		}

		fmt.Printf(" %s@%s requires %s: %s\n", pkgName, latestVersion, nextPkgName, nextVersionConstraint)

		// create a new purl - like we updated the purl in the next iteration
		// image A --> B
		// we updated A to A', now we check the new version of B
		// Important: copy qualifiers (arch, distro) from original PURL to preserve suite/arch info
		nextPURL := packageurl.PackageURL{
			Type:       purls[i+1].Type,
			Name:       purls[i+1].Name,
			Qualifiers: purls[i+1].Qualifiers,
			// we do not define version right here
			// since versionConstraint might be a range or a constraint, we want to fetch ALL versions of that package and then resolve the versionConstraint to a specific version using the resolver's ResolveBestVersion function
		}

		nextAllVersionsMeta, err := resolver.FetchPackageMetadata(nextPURL)
		if err != nil {
			return "", fmt.Errorf("failed to fetch all versions for %s: %w", nextPkgName, err)
		}

		nextBestVersion, err := resolver.ResolveBestVersion(nextAllVersionsMeta, nextVersionConstraint, purls[i+1].Version)
		if err != nil {
			return "", fmt.Errorf("failed to resolve version for %s with spec %s: %w", nextPkgName, nextVersionConstraint, err)
		}

		purls[i+1].Version = nextBestVersion
		fmt.Printf(" Resolved %s to version: %s\n", nextPkgName, nextBestVersion)
	}

	vulnPkgName := purls[len(purls)-1].Name
	vulnVersion := purls[len(purls)-1].Version

	// Version format validation is delegated to resolver's CheckIfVulnerabilityIsFixed
	// (each resolver validates according to its version scheme)

	// Check if vulnerability is fixed using resolver-specific comparison
	isFixed := resolver.CheckIfVulnerabilityIsFixed(vulnVersion, fixedVersion)

	if isFixed {
		fixingVersion := purls[0].Name + "@" + purls[0].Version
		return fixingVersion, nil
	}

	fmt.Printf("Fix not verified: %s@%s is < %s\n", vulnPkgName, vulnVersion, fixedVersion)
	return "", nil
}

func main() {

	// ["debian@12.8","pkg:deb/debian/apt@2.6.1A~5.2.0.202311171811?arch=amd64&distro=debian-12.8","pkg:deb/debian/adduser@3.134.0?arch=all&distro=debian-12.8","pkg:deb/debian/passwd@1:4.13+dfsg1-1+deb12u1?arch=amd64&distro=debian-12.8&epoch=1"]
	purl3, _ := packageurl.FromString("pkg:deb/debian/apt@2.6.1A~5.2.0.202311171811?arch=amd64&distro=debian-12.8")
	purl2, _ := packageurl.FromString("pkg:deb/debian/adduser@3.134.0?arch=all&distro=debian-12.8")
	purl1, _ := packageurl.FromString("pkg:deb/debian/passwd@1:4.13+dfsg1-1+deb12u1?arch=amd64&distro=debian-12.8&epoch=1")

	purls := []packageurl.PackageURL{
		purl1,
		purl2,
		purl3,
	}

	// in component_fixed_version in database
	fixedVersion := "1:4.0.14-9"

	resolver := &DebianResolver{}

	fixingVersion, err := checkVulnerabilityFixChain(resolver, purls, fixedVersion)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(fixingVersion)
	// Example output: nextra-theme-docs@3.4.0 (or similar if a fix is found)

}
