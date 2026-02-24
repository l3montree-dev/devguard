// Copyright 2026 larshermges
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
func (resolver *NPMResolver) GetRecommendedVersions(npmResponse *NPMResponse, currentVersion string) ([]string, error) {

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

func (resolver *NPMResolver) ResolveBestVersion(allVersionsMeta *NPMResponse, versionConstraint VersionConstraint, currentVersion string) (string, error) {
	versionConstraintStr := strings.TrimSpace(string(versionConstraint))

	// Handle OR expressions - not implemented yet, return error
	// if strings.Contains(versionConstraint, "||") {
	// 	return "", fmt.Errorf("OR expressions (||) not yet supported: %s", versionConstraint)
	// }

	var rangeType string
	var baseVersion string
	var baseVersions []string
	// Determine range type and extract base version
	if strings.Contains(versionConstraintStr, "||") {
		rangeType = "||"
		baseVersions = splitOrExpression(versionConstraintStr)
	} else {
		rangeType, baseVersion = parseVersionConstraint(versionConstraintStr)
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
				orRangeType, orBaseVersion := parseVersionConstraint(orSpec)

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

	if pkg.Version != "" {
		req, err = httpClient.Get("https://registry.npmjs.org/" + pkg.Name + "/" + normalizedVersion)
	} else {
		req, err = httpClient.Get("https://registry.npmjs.org/" + pkg.Name)
	}

	if err != nil {
		if req != nil {
			req.Body.Close()
		}
		return nil, err
	}

	if req.StatusCode != 200 {
		req.Body.Close()
		return nil, fmt.Errorf("failed to fetch data for %s: %s", pkg.Name, req.Status)
	}
	return req, nil
}
