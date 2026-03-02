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
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/semver"
)

type NPMResolver struct{}

var _ Resolver[*NPMResponse] = &NPMResolver{}

func (resolver *NPMResolver) ParseVersionConstraint(spec string) (rangeType string, baseVersion string) {
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

func (resolver *NPMResolver) FetchPackageMetadata(purl packageurl.PackageURL) (*NPMResponse, error) {
	resp, err := getNPMRegistry(purl)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %w", purl.ToString(), err)
	}
	defer resp.Body.Close()

	var npmResp NPMResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, fmt.Errorf("error decoding JSON for %s: %w", purl.ToString(), err)
	}

	return &npmResp, nil
}

// this currently implements the versioning algorithm for "always take latest"
func (resolver *NPMResolver) GetUpgradeCandidates(npmResponse *NPMResponse, currentVersion string) ([]string, error) {

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

func (resolver *NPMResolver) getAllDependencyMaps(depMeta *NPMResponse) []map[string]string {
	return []map[string]string{
		depMeta.Dependencies,
		depMeta.PeerDependencies,
		depMeta.OptionalDependencies,
		depMeta.DevDependencies,
	}
}

func (resolver *NPMResolver) FindDependencyVersionInMeta(depMeta *NPMResponse, pkgName string) VersionConstraint {
	for _, depType := range resolver.getAllDependencyMaps(depMeta) {
		if version, ok := depType[pkgName]; ok {
			return VersionConstraint(version)
		}
	}
	return ""
}

// resolveBestVersion finds the best matching version given a version spec and all available versions
// versionConstraint examples: "15.4.7", "^15.0.0", "~15.4.0", ">15.0.0", ">=15.4.0"
// Also supports incomplete semver like "^14.0", "^14", "~15", etc.
// Returns the highest matching version, or error if no match or spec is invalid
func (resolver *NPMResolver) ResolveBestVersion(allVersionsMeta *NPMResponse, versionConstraint VersionConstraint, currentVersion string) (string, error) {
	versionConstraintStr := strings.TrimSpace(string(versionConstraint))

	var rangeType string
	var baseVersion string
	var baseVersions []string
	// Determine range type and extract base version
	if strings.Contains(versionConstraintStr, "||") {
		rangeType = "||"
		baseVersions = splitOrExpression(versionConstraintStr)
	} else {
		rangeType, baseVersion = resolver.ParseVersionConstraint(versionConstraintStr)
		// Normalize incomplete semver versions (e.g., "14.0" -> "14.0.0", "14" -> "14.0.0")
		baseVersion = normalizeVersion(baseVersion)
	}

	if rangeType != "||" && !semver.IsValid("v"+baseVersion) {
		return "", fmt.Errorf("invalid semver in spec: %s", versionConstraint)
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
			matches = matchesVersionConstraint(rangeType, v, vParts, baseVersion, baseParts)
		case "||":
			for _, orSpec := range baseVersions {
				orRangeType, orBaseVersion := resolver.ParseVersionConstraint(orSpec)

				// Normalize incomplete semver versions (e.g., "14.0" -> "14.0.0", "14" -> "14.0.0")
				orBaseVersionNormalized := normalizeVersion(orBaseVersion)

				if !semver.IsValid("v" + orBaseVersionNormalized) {
					continue // Skip invalid specs after normalization
				}

				orBaseParts := parseVersion(orBaseVersionNormalized)

				// Check if current version matches this OR spec
				orMatches := matchesVersionConstraint(orRangeType, v, vParts, orBaseVersionNormalized, orBaseParts)

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
			return "", fmt.Errorf("no versions match spec %s", versionConstraint)
		}
		return "", fmt.Errorf("no versions match spec %s in major version %d", versionConstraint, baseParts[0])
	}

	// Sort candidates and return the highest version
	sort.Slice(candidates, func(i, j int) bool {
		return semver.Compare("v"+candidates[i], "v"+candidates[j]) > 0
	})

	return candidates[0], nil
}

func (resolver *NPMResolver) CheckIfVulnerabilityIsFixed(vulnVersion string, fixedVersion string) bool {
	return semver.Compare("v"+vulnVersion, "v"+fixedVersion) >= 0
}

// get all versions if no version is specified
func getNPMRegistry(pkg packageurl.PackageURL) (*http.Response, error) {
	var req *http.Response
	var err error

	normalizedVersion := strings.Trim(pkg.Version, "/") // remove quotes if present

	// Build full package name (handles scoped packages like @babel/core)
	fullName := pkg.Name
	if pkg.Namespace != "" {
		fullName = pkg.Namespace + "/" + pkg.Name
	}

	if pkg.Version != "" {
		req, err = httpClient.Get("https://registry.npmjs.org/" + fullName + "/" + normalizedVersion)
	} else {
		req, err = httpClient.Get("https://registry.npmjs.org/" + fullName)
	}

	if err != nil {
		if req != nil {
			req.Body.Close()
		}
		return nil, err
	}

	if req.StatusCode != 200 {
		req.Body.Close()
		return nil, fmt.Errorf("failed to fetch data for %s: %s", fullName, req.Status)
	}
	return req, nil
}
