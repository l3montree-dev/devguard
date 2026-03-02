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

type VersionConstraint string

type Resolver[T any] interface {
	FetchPackageMetadata(purl packageurl.PackageURL) (T, error)
	GetUpgradeCandidates(allVersionsMeta T, currentVersion string) ([]string, error)
	FindDependencyVersionInMeta(depMeta T, pkgName string) VersionConstraint
	ResolveBestVersion(allVersionsMeta T, versionConstraint VersionConstraint, currentVersion string) (string, error)
	CheckIfVulnerabilityIsFixed(vulnVersion string, fixedVersion string) bool
	ParseVersionConstraint(spec string) (rangeType string, baseVersion string)
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
			versions, err := resolver.GetUpgradeCandidates(allVersionsMeta, currentVersion)
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
		if latestVersion != currentVersion {
			fmt.Printf("Found newer version for %s: %s -> %s\n", pkgName, currentVersion, latestVersion)
		} else {
			fmt.Printf("Using current version for %s: %s\n", pkgName, currentVersion)
		}

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
		nextPURL := purls[i+1]
		nextPURL.Version = "" // Clear version since we'll resolve it with ResolveBestVersion

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

func CheckVulnerabilityFixChainAuto(purls []packageurl.PackageURL, fixedVersion string) (string, error) {
	if len(purls) == 0 {
		return "", fmt.Errorf("no PURLs provided")
	}

	switch purls[0].Type {
	case "deb":
		resolver := &DebianResolver{}
		return checkVulnerabilityFixChain(resolver, purls, fixedVersion)
	case "npm":
		resolver := &NPMResolver{}
		return checkVulnerabilityFixChain(resolver, purls, fixedVersion)
	default:
		return "", fmt.Errorf("unsupported package type: %s", purls[0].Type)
	}
}

func main() {

	//Problem:
	/*

		["pkg:deb/debian/build-essential@12.12?arch=arm64","pkg:deb/debian/g++@14.2.0-1?arch=arm64","pkg:deb/debian/g++-14@14.2.0-19?arch=arm64","pkg:deb/debian/g++-14-aarch64-linux-gnu@14.2.0-19?arch=arm64","pkg:deb/debian/libstdc++-14-dev@14.2.0-19?arch=arm64","pkg:deb/debian/libc6-dev@2.41-12+deb13u1?arch=arm64"]

		["pkg:deb/debian/curl@8.14.1-2+deb13u2?arch=arm64","pkg:deb/debian/libcurl4t64@8.14.1-2+deb13u2?arch=arm64","pkg:deb/debian/librtmp1@2.4+20151223.gitfa8646d.1-2+b5?arch=arm64","pkg:deb/debian/libgnutls30t64@3.8.9-3+deb13u2?arch=arm64","pkg:deb/debian/libp11-kit0@0.25.5-3?arch=arm64"]


		["pkg:deb/debian/coreutils@9.7-3?arch=arm64","pkg:deb/debian/libsystemd0@257.9-1~deb13u1?arch=arm64","pkg:deb/debian/libcap2@2.75-10+b3?arch=arm64"]


		This example is an actual fix for a quickfix, resolve : 1:5.19-2
		["pkg:deb/debian/file@5.46-5?arch=arm64","pkg:deb/debian/libmagic1t64@5.46-5?arch=arm64","pkg:deb/debian/libmagic-mgc@5.46-5?arch=arm64"]

		["pkg:deb/debian/nano@8.4-1?arch=arm64","pkg:deb/debian/libncursesw6@6.5+20250216-2?arch=arm64","pkg:deb/debian/libtinfo6@6.5+20250216-2?arch=arm64"]

		["pkg:deb/debian/git@1:2.47.3-0+deb13u1?arch=arm64","pkg:deb/debian/libcurl3t64-gnutls@8.14.1-2+deb13u2?arch=arm64","pkg:deb/debian/libngtcp2-crypto-gnutls8@1.11.0-1?arch=arm64","pkg:deb/debian/libgnutls30t64@3.8.9-3+deb13u2?arch=arm64","pkg:deb/debian/libtasn1-6@4.20.0-2?arch=arm64"]

	*/
	purl1, _ := packageurl.FromString("pkg:deb/debian/git@1:2.47.3-0+deb13u1?arch=arm64")
	purl2, _ := packageurl.FromString("pkg:deb/debian/libcurl3t64-gnutls@8.14.1-2+deb13u2?arch=arm64")
	purl3, _ := packageurl.FromString("pkg:deb/debian/libngtcp2-crypto-gnutls8@1.11.0-1?arch=arm64")
	purl4, _ := packageurl.FromString("pkg:deb/debian/libgnutls30t64@3.8.9-3+deb13u2?arch=arm64")
	purl5, _ := packageurl.FromString("pkg:deb/debian/libtasn1-6@4.20.0-2?arch=arm64")

	purls := []packageurl.PackageURL{
		purl1,
		purl2,
		purl3,
		purl4,
		purl5,
	}

	// in component_fixed_version in database
	fixedVersion := "4.21.0-2"

	fixingVersion, err := CheckVulnerabilityFixChainAuto(purls, fixedVersion)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(fixingVersion)

}
