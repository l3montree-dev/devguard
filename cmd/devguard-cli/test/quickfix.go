// Copyright 2026 larshermges @ l3montree GmbH

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

func getPackageManager(Package string) string {
	// insert future Package Managers later
	switch Package {

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
	}
	// add more in the future
	return nil, nil
}

func getRecommendedVersions(npmResponse NPMResponse, currentVersion string) ([]string, error) {
	var versions [][]string

	// Extract and filter versions from NPMResponse
	for _, obj := range npmResponse.Versions {
		// skip release candidates
		if strings.Contains(obj.Version, "-") {
			continue
		}
		versionParts := strings.Split(obj.Version, ".")
		versions = append(versions, versionParts)
	}

	// Filter by major version and sort
	var currentMajor, currentMinor, currentPatch int
	fmt.Sscanf(currentVersion, "%d.%d.%d", &currentMajor, &currentMinor, &currentPatch)

	var recommended []string
	for _, version := range versions {
		var major, minor, patch int
		versionStr := strings.Join(version, ".")
		fmt.Sscanf(versionStr, "%d.%d.%d", &major, &minor, &patch)

		if major == currentMajor {
			if minor >= currentMinor {
				if patch >= currentPatch {
					recommended = append(recommended, versionStr)
				}
			}
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

	fmt.Println(recommended)
	return recommended, nil
}

func parseVersion(version string) [3]int {
	var result [3]int
	fmt.Sscanf(version, "%d.%d.%d", &result[0], &result[1], &result[2])
	return result
}

// single node in the dependency tree
type DependencyNode struct {
	Name         string
	Version      string
	Dependencies map[string]*DependencyNode
}

func IsValidSemver(version string) bool {

	pattern := `^\d+\.\d+\.\d+$`
	matched, _ := regexp.MatchString(pattern, version)
	return matched
}

func processDependencies(depMap map[string]string, depName string, depVersion string, visited map[string]bool, vulnerablePackage string, vulnerableVersion string, node *DependencyNode) {
	for depKey, depVal := range depMap {
		// remove ^, ~, quotes
		normalizedDepVal := strings.Trim(depVal, "^~\"")

		// Skip non-semver versions
		if !IsValidSemver(normalizedDepVal) {
			continue
		}

		// Check if version exists before fetching
		if !VersionExists(depKey, normalizedDepVal) {
			fmt.Printf("Skipping %s@%s: version not found\n", depKey, normalizedDepVal)
			continue
		}

		depResp, err := GetNPMRegistry(RegistryRequest{Dependency: depKey, Version: depVal})
		if err != nil {
			fmt.Printf("Error fetching %s@%s: %v\n", depKey, depVal, err)
			continue
		}

		depBody, err := io.ReadAll(depResp.Body)
		depResp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading response for %s@%s: %v\n", depKey, depVal, err)
			continue
		}

		// Recursive call
		childNode := walkDependencyTree(depBody, depKey, depVal, visited, vulnerablePackage, vulnerableVersion)
		if childNode != nil {
			node.Dependencies[depKey] = childNode
		}
		if depKey == vulnerablePackage && depVal == vulnerableVersion {
			fmt.Printf("Vulnerable package found: %s@%s\n", depKey, depVal)
		}
	}
}

func walkDependencyTree(npmRegisterResp []byte, depName string, depVersion string, visited map[string]bool, vulnerablePackage string, vulnerableVersion string) *DependencyNode {
	var jsonData NPMResponse

	if err := json.Unmarshal(npmRegisterResp, &jsonData); err != nil {
		return nil
	}

	nodeKey := depName + "@" + depVersion
	if visited[nodeKey] {
		return nil
	}
	visited[nodeKey] = true

	node := &DependencyNode{
		Name:         depName,
		Version:      depVersion,
		Dependencies: make(map[string]*DependencyNode),
	}

	if jsonData.Dependencies == nil && jsonData.DevDependencies == nil && jsonData.PeerDependencies == nil && jsonData.OptionalDependencies == nil {
		return node
	}

	// Process all dependency types using the same logic
	processDependencies(jsonData.Dependencies, depName, depVersion, visited, vulnerablePackage, vulnerableVersion, node)
	processDependencies(jsonData.OptionalDependencies, depName, depVersion, visited, vulnerablePackage, vulnerableVersion, node)
	processDependencies(jsonData.DevDependencies, depName, depVersion, visited, vulnerablePackage, vulnerableVersion, node)

	return node
}

func printDependencyTree(node *DependencyNode, indent string) {
	if node == nil {
		return
	}

	fmt.Printf("%s%s@%s\n", indent, node.Name, node.Version)

	for _, dep := range node.Dependencies {
		printDependencyTree(dep, indent+"  ")
	}
}

func findDependencyVersion(npmResp NPMResponse, depName string) string {
	// Check all dependency types
	if version, ok := npmResp.Dependencies[depName]; ok {
		return version
	}
	if version, ok := npmResp.OptionalDependencies[depName]; ok {
		return version
	}
	if version, ok := npmResp.DevDependencies[depName]; ok {
		return version
	}
	if version, ok := npmResp.PeerDependencies[depName]; ok {
		return version
	}
	return ""
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

func checkVersionAvailability(versions []string, currentVersion string) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions available")
	}

	if versions[0] == currentVersion {
		return "", fmt.Errorf("no new version available (current: %s)", currentVersion)
	}

	return versions[0], nil
}

func checkVulnerabilityStatus(latestMeta *NPMResponse, vulnPkg string, vulnVer string) (bool, string) {
	latestVulnVer := findDependencyVersion(*latestMeta, vulnPkg)

	if latestVulnVer == vulnVer {
		return false, latestVulnVer
	}

	if latestVulnVer != "" && latestVulnVer != vulnVer {
		return true, latestVulnVer
	}

	return false, latestVulnVer
}

func checkVulnerabilityFix(directDep string, currentVer string, vulnPkg string, vulnVer string) error {

	npmMeta, err := fetchPackageMetadata(getPackageManager("npm"), directDep, "")
	if err != nil {
		return fmt.Errorf("failed to fetch package metadata: %w", err)
	}

	versions, err := getRecommendedVersions(*npmMeta, currentVer)
	if err != nil {
		return fmt.Errorf("failed to filter versions: %w", err)
	}

	latestVer, err := checkVersionAvailability(versions, currentVer)
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Printf("New versions available for %s: %s -> %s\n", directDep, currentVer, latestVer)

	latestMeta, err := fetchPackageMetadata(getPackageManager("npm"), directDep, "latest")
	if err != nil {
		return fmt.Errorf("failed to fetch latest version metadata: %w", err)
	}

	isFixed, newVer := checkVulnerabilityStatus(latestMeta, vulnPkg, vulnVer)

	if !isFixed {
		fmt.Printf("Vulnerability NOT fixed in latest %s (still uses %s@%s)\n", directDep, vulnPkg, vulnVer)
		return nil
	}

	fmt.Printf("✓ Vulnerability FIXED in latest (uses %s@%s instead of %s)\n", vulnPkg, newVer, vulnVer)
	return nil
}

func main() {
	directDependency := "playwright"
	currentVersion := "1.50.1"
	directVulnerablePackage := "fsevents"
	directVulnerableVersion := "2.3.2"
	// transitiveVulnerablePackage := "ip"
	// transitiveVulnerableVersion := "1.1.5"

	if err := checkVulnerabilityFix(directDependency, currentVersion, directVulnerablePackage, directVulnerableVersion); err != nil {
		fmt.Println("Error:", err)
	}
}
