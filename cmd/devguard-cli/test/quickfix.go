// Copyright 2026 lars hermges @ l3montree GmbH

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
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
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
	}
	return "unknown"
}

func getVersion(packageManager string, pkg RegistryRequest) (*http.Response, error) {

	switch packageManager {
	case "node":
		return GetNPMRegistry(pkg)
	case "crates":
		return GetCratesRegistry(pkg)
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", packageManager)
	}
}

// this currently implements the versioning algorithm for "always take latest"
func getRecommendedVersions(npmResponse NPMResponse, currentVersion string) ([]string, error) {

	var versions [][]string

	for _, obj := range npmResponse.Versions {
		// skip release candidates
		if strings.Contains(obj.Version, "-") {
			continue
		}
		versionParts := strings.Split(obj.Version, ".")
		versions = append(versions, versionParts)
	}

	var currentMajor, currentMinor, currentPatch int
	if _, err := fmt.Sscanf(currentVersion, "%d.%d.%d", &currentMajor, &currentMinor, &currentPatch); err != nil {
		return nil, fmt.Errorf("invalid current version format: %s", currentVersion)
	}

	var recommended []string
	for _, version := range versions {
		versionStr := strings.Join(version, ".")
		if !semver.IsValid("v" + versionStr) {
			continue
		}

		vSemver := "v" + versionStr
		currentSemver := "v" + currentVersion

		if semver.Major(vSemver) == semver.Major(currentSemver) && semver.Compare(vSemver, currentSemver) >= 0 {
			recommended = append(recommended, versionStr)
		}
	}

	sort.Slice(recommended, func(i, j int) bool {
		vi := parseVersion(recommended[i])
		vj := parseVersion(recommended[j])
		if vi[0] != vj[0] {
			return vi[0] > vj[0]
		}
		if vi[1] != vj[1] {
			return vi[1] > vj[1]
		}
		return vi[2] > vj[2]
	})

	return recommended, nil
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

func parsePurl(purl string) (string, string, error) {
	// Format: pkg:npm/package-name@version or pkg:npm/@scoped/package@version
	// Note: version can be empty string to indicate "all versions" (see RegistryRequest)
	input, err := packageurl.FromString(purl)
	if err != nil {
		return "", "", fmt.Errorf("invalid purl format: %w", err)
	}

	pkgName := input.Name
	if input.Namespace != "" {
		pkgName = input.Namespace + "/" + input.Name
	}

	version := input.Version

	return pkgName, version, nil
}

func getAllDependencyMaps(depMeta *NPMResponse) []map[string]string {
	return []map[string]string{
		depMeta.Dependencies,
		depMeta.PeerDependencies,
		depMeta.OptionalDependencies,
		depMeta.DevDependencies,
	}
}

func findDependencyVersionInMeta(depMeta *NPMResponse, pkgName string) string {
	for _, depType := range getAllDependencyMaps(depMeta) {
		if version, ok := depType[pkgName]; ok {
			return version
		}
	}
	return ""
}
func splitOrExpression(versionSpec string) []string {
	parts := strings.Split(versionSpec, "||")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func matchesVersionSpec(rangeType string, version string, versionParts [3]int, baseVersion string, baseParts [3]int) bool {
	switch rangeType {
	case "^":
		// Caret: same major version, >= base
		return versionParts[0] == baseParts[0] && semver.Compare("v"+version, "v"+baseVersion) >= 0

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

// parseVersionSpec extracts the range type and base version from a version spec
// Returns the range type ("^", "~", ">=", ">", "exact") and the trimmed base version
// Pre-release versions are stripped (e.g., "15.0.0-rc.0" becomes "15.0.0")
func parseVersionSpec(spec string) (rangeType string, baseVersion string) {
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
// versionSpec examples: "15.4.7", "^15.0.0", "~15.4.0", ">15.0.0", ">=15.4.0"
// Also supports incomplete semver like "^14.0", "^14", "~15", etc.
// Returns the highest matching version, or error if no match or spec is invalid
func resolveBestVersion(allVersionsMeta *NPMResponse, versionSpec string, currentVersion string) (string, error) {
	versionSpec = strings.TrimSpace(versionSpec)

	// Handle OR expressions - not implemented yet, return error
	// if strings.Contains(versionSpec, "||") {
	// 	return "", fmt.Errorf("OR expressions (||) not yet supported: %s", versionSpec)
	// }

	var rangeType string
	var baseVersion string
	var baseVersions []string
	// Determine range type and extract base version
	if strings.Contains(versionSpec, "||") {
		rangeType = "||"
		baseVersions = splitOrExpression(versionSpec)
	} else {
		rangeType, baseVersion = parseVersionSpec(versionSpec)
		// Normalize incomplete semver versions (e.g., "14.0" -> "14.0.0", "14" -> "14.0.0")
		baseVersion = normalizeVersion(baseVersion)
	}

	if rangeType != "||" && !semver.IsValid("v"+baseVersion) {
		return "", fmt.Errorf("invalid semver in spec: %s", versionSpec)
	}

	// For exact version, simply return the requested version; equality with currentVersion is allowed
	if rangeType == "exact" {
		if baseVersion == currentVersion {
			return "", fmt.Errorf("exact version %s is same as current version, no upgrade possible", baseVersion)
		}
		return baseVersion, nil
	}

	baseParts := parseVersion(baseVersion)
	var candidates []string

	// Collect matching versions from all available versions
	for _, versionObj := range allVersionsMeta.Versions {
		v := versionObj.Version

		// Skip pre-release versions (containing -)
		if strings.Contains(v, "-") {
			continue
		}

		if !semver.IsValid("v" + v) {
			continue
		}

		vParts := parseVersion(v)
		matches := false

		switch rangeType {
		case "^", "~", ">=", ">":
			matches = matchesVersionSpec(rangeType, v, vParts, baseVersion, baseParts)
		case "||":
			for _, orSpec := range baseVersions {
				orRangeType, orBaseVersion := parseVersionSpec(orSpec)

				// Normalize incomplete semver versions (e.g., "14.0" -> "14.0.0", "14" -> "14.0.0")
				orBaseVersionNormalized := normalizeVersion(orBaseVersion)

				if !semver.IsValid("v" + orBaseVersionNormalized) {
					continue // Skip invalid specs after normalization
				}

				orBaseParts := parseVersion(orBaseVersionNormalized)

				// Check if current version matches this OR spec
				orMatches := matchesVersionSpec(orRangeType, v, vParts, orBaseVersionNormalized, orBaseParts)

				// If any OR element matches, the whole OR expression matches
				if orMatches {
					matches = true
					break
				}
			}
		}

		if matches {
			candidates = append(candidates, v)
		}
	}

	if len(candidates) == 0 {
		if rangeType == "||" {
			return "", fmt.Errorf("no versions match spec %s", versionSpec)
		}
		return "", fmt.Errorf("no versions match spec %s in major version %d", versionSpec, baseParts[0])
	}

	// Sort candidates and return the highest version
	sort.Slice(candidates, func(i, j int) bool {
		return semver.Compare("v"+candidates[i], "v"+candidates[j]) > 0
	})

	return candidates[0], nil
}

func checkVulnerabilityFixChain(purls []string, fixedVersion string) (string, error) {

	if len(purls) < 2 {
		return "", fmt.Errorf("purl array must contain at least 2 elements")
	}

	if !semver.IsValid("v" + fixedVersion) {
		return "", fmt.Errorf("fixed version has invalid semver format")
	}

	packages := make([]struct {
		name    string
		version string
	}, len(purls))

	for i, purl := range purls {
		name, version, err := parsePurl(purl)
		if err != nil {
			return "", err
		}
		// In the context of dependency chains, versions are required (not "all versions")
		if version == "" {
			return "", fmt.Errorf("dependency chain purl must include version: %s", purl)
		}
		packages[i].name = name
		packages[i].version = version
	}

	for i := 0; i < len(packages)-1; i++ {
		pkgName := packages[i].name
		currentVersion := packages[i].version

		// fetch all version
		allVersionsMeta, err := fetchPackageMetadata(pkgName, "")
		if err != nil {
			return "", fmt.Errorf("failed to fetch all versions for %s: %w", pkgName, err)
		}

		var latestVersion string
		if i == 0 {
			versions, err := getRecommendedVersions(*allVersionsMeta, currentVersion)
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

		packages[i].version = latestVersion
		fmt.Printf("Found newer version for %s: %s to %s\n", pkgName, currentVersion, latestVersion)

		// Second: check latest version
		latestMeta, err := fetchPackageMetadata(pkgName, latestVersion)
		if err != nil {
			return "", fmt.Errorf("failed to fetch latest metadata for %s@%s: %w", pkgName, latestVersion, err)
		}

		nextPkgName := packages[i+1].name

		nextVersionSpec := findDependencyVersionInMeta(latestMeta, nextPkgName)
		if nextVersionSpec == "" {
			return "", fmt.Errorf("package %s not found in %s@%s dependencies", nextPkgName, pkgName, latestVersion)
		}

		fmt.Printf(" %s@%s requires %s: %s\n", pkgName, latestVersion, nextPkgName, nextVersionSpec)

		nextAllVersionsMeta, err := fetchPackageMetadata(nextPkgName, "")
		if err != nil {
			return "", fmt.Errorf("failed to fetch all versions for %s: %w", nextPkgName, err)
		}

		nextBestVersion, err := resolveBestVersion(nextAllVersionsMeta, nextVersionSpec, packages[i+1].version)
		if err != nil {
			return "", fmt.Errorf("failed to resolve version for %s with spec %s: %w", nextPkgName, nextVersionSpec, err)
		}

		packages[i+1].version = nextBestVersion
		fmt.Printf(" Resolved %s to version: %s\n", nextPkgName, nextBestVersion)
	}

	vulnPkgName := packages[len(packages)-1].name
	vulnVersion := packages[len(packages)-1].version

	if !semver.IsValid("v" + vulnVersion) {
		return "", fmt.Errorf("vulnerable package has invalid semver: %s@%s", vulnPkgName, vulnVersion)
	}

	// Check if vulnerability is fixed using semver comparison
	isFixed := semver.Compare("v"+vulnVersion, "v"+fixedVersion) >= 0

	if isFixed {
		fixingVersion := packages[0].name + "@" + packages[0].version
		return fixingVersion, nil
	}

	fmt.Printf("Fix not verified: %s@%s is < %s\n", vulnPkgName, vulnVersion, fixedVersion)
	return "", nil
}

func fetchPackageMetadata(dep string, version string) (*NPMResponse, error) {
	resp, err := getVersion("node", RegistryRequest{Dependency: dep, Version: version})
	if err != nil {
		return nil, fmt.Errorf("error fetching %s@%s: %w", dep, version, err)
	}
	defer resp.Body.Close()

	var npmResp NPMResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, fmt.Errorf("error decoding JSON for %s@%s: %w", dep, version, err)
	}

	return &npmResp, nil
}

func main() {
	purls := []string{
		"pkg:npm/@ory/integrations@1.3.1",
		/*
			nextjs@9.39.0 ---> Ist abhängig von react@6.28.0

			packages[i+1].version = 6.28.0
			1. Erneut getRecommendedVersions für react@6.28.0??? Aber ist doch fixed von nextjs
			Wenn ^react@6.28.0 in nextjs@9.39.0
		*/
		"pkg:npm/next@15.4.7",
	}

	// in component_fixed_version in database
	fixedVersion := "15.4.8"

	fixingVersion, err := checkVulnerabilityFixChain(purls, fixedVersion)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(fixingVersion)
}
