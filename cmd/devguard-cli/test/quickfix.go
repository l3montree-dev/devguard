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
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/semver"
)

func getPackageManager(pkg string) string {
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
		if !IsValidSemver(versionStr) {
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
	if _, err := fmt.Sscanf(version, "%d.%d.%d", &result[0], &result[1], &result[2]); err != nil {
		return [3]int{0, 0, 0}
	}
	return result
}

// single node in the dependency tree

func IsValidSemver(version string) bool {

	pattern := `^\d+\.\d+\.\d+$`
	matched, _ := regexp.MatchString(pattern, version)
	return matched
}

func parsePurl(purl string) (string, string, error) {
	// Format: pkg:npm/package-name@version or pkg:npm/@scoped/package@version
	input, err := packageurl.FromString(purl)
	if err != nil {
		return "", "", fmt.Errorf("invalid purl format: %w", err)
	}

	pkgName := input.Name
	if input.Namespace != "" {
		pkgName = input.Namespace + "/" + input.Name
	}

	version := input.Version
	if version == "" {
		return "", "", fmt.Errorf("invalid purl format: missing version")
	}

	return pkgName, version, nil
}

func normalizeVersion(version string) string {
	return strings.Trim(version, "^~\"")
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

func checkVulnerabilityFixChain(purls []string, fixedVersion string) (string, error) {

	if len(purls) < 2 {
		return "", fmt.Errorf("purl array must contain at least 2 elements")
	}

	if !IsValidSemver(fixedVersion) {
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
		packages[i].name = name
		packages[i].version = version
	}

	for i := 0; i < len(packages)-1; i++ {
		pkgName := packages[i].name
		currentVersion := packages[i].version

		// fetch all version
		allVersionsMeta, err := fetchPackageMetadata(getPackageManager("npm"), pkgName, "")
		if err != nil {
			return "", fmt.Errorf("failed to fetch all versions for %s: %w", pkgName, err)
		}

		var latestVersion string
		if i == 0 {
			// get major versions and sort
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
			// if packageurl.
		}

		fmt.Printf("Found newer version for %s: %s to %s\n", pkgName, currentVersion, latestVersion)

		// Second: check latest version
		latestMeta, err := fetchPackageMetadata(getPackageManager("npm"), pkgName, latestVersion)
		if err != nil {
			return "", fmt.Errorf("failed to fetch latest metadata for %s@%s: %w", pkgName, latestVersion, err)
		}

		nextPkgName := packages[i+1].name

		nextVersionInLatest := findDependencyVersionInMeta(latestMeta, nextPkgName)
		if nextVersionInLatest == "" {
			return "", fmt.Errorf("package %s not found in %s@%s dependencies", nextPkgName, pkgName, latestVersion)
		}

		normalizedNextVersion := normalizeVersion(nextVersionInLatest)
		fmt.Printf(" %s found in %s@%s dependencies: %s\n", nextPkgName, pkgName, latestVersion, normalizedNextVersion)

		packages[i+1].version = normalizedNextVersion
	}

	vulnPkgName := packages[len(packages)-1].name
	vulnVersion := packages[len(packages)-1].version

	if !IsValidSemver(vulnVersion) {
		return "", fmt.Errorf("vulnerable package has invalid semver: %s@%s", vulnPkgName, vulnVersion)
	}

	// Parse versions to compare
	vulnParts := parseVersion(vulnVersion)
	fixedParts := parseVersion(fixedVersion)

	isFixed := false
	if vulnParts[0] > fixedParts[0] {
		isFixed = true
	} else if vulnParts[0] == fixedParts[0] {
		if vulnParts[1] > fixedParts[1] {
			isFixed = true
		} else if vulnParts[1] == fixedParts[1] {
			if vulnParts[2] >= fixedParts[2] {
				isFixed = true
			}
		}
	}

	if isFixed {
		fixingVersion := packages[0].name + "@" + packages[0].version
		return fixingVersion, nil
	}

	fmt.Printf("Fix not verified: %s@%s is < %s\n", vulnPkgName, vulnVersion, fixedVersion)
	return "", nil
}

func fetchPackageMetadata(pkgManager string, dep string, version string) (*NPMResponse, error) {
	resp, err := getVersion(pkgManager, RegistryRequest{Dependency: dep, Version: version})
	if err != nil {
		return nil, fmt.Errorf("error fetching %s@%s: %w", dep, version, err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading response for %s@%s: %w", dep, version, err)
	}

	var npmResp NPMResponse
	if err := json.Unmarshal(body, &npmResp); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON for %s@%s: %w", dep, version, err)
	}

	return &npmResp, nil
}

func main() {
	purls := []string{
		"pkg:npm/@sentry/nextjs@9.38.0",
		/*
			nextjs@9.39.0 ---> Ist abhängig von react@6.28.0

			packages[i+1].version = 6.28.0
			1. Erneut getRecommendedVersions für react@6.28.0??? Aber ist doch fixed von nextjs
			Wenn ^react@6.28.0 in nextjs@9.39.0
		*/
		"pkg:npm/next@15.4.7",
	}

	// in component_fixed_version in database
	fixedVersion := "15.4.9"

	fixingVersion, err := checkVulnerabilityFixChain(purls, fixedVersion)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(fixingVersion)
}
