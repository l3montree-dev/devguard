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

package fixedversion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/singleflight"
)

const (
	npmPackumentCacheSize = 10_000
	npmPackumentCacheTTL  = 3 * time.Hour
	npmRequestTimeout     = 60 * time.Second
)

type NPMResolver struct {
	// the same packages show up in the paths of many vulns - caching them keeps us below the egress rate limit
	packuments *expirable.LRU[string, *NPMResponse]
	inflight   singleflight.Group
}

func NewNPMResolver() *NPMResolver {
	return &NPMResolver{
		packuments: expirable.NewLRU[string, *NPMResponse](npmPackumentCacheSize, nil, npmPackumentCacheTTL),
	}
}

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

func matchesVersionConstraint(rangeType string, version string, baseVersion string) bool {
	vV := "v" + version
	vB := "v" + baseVersion

	switch rangeType {
	case "^":
		// ^0.2.3 → same minor band; ^0.0.3 → exact patch; ^1.2.3 → same major
		if semver.Major(vB) != "v0" {
			return semver.Major(vV) == semver.Major(vB) && semver.Compare(vV, vB) >= 0
		} else if semver.MajorMinor(vB) != "v0.0" {
			return semver.MajorMinor(vV) == semver.MajorMinor(vB) && semver.Compare(vV, vB) >= 0
		}
		return semver.Canonical(vV) == semver.Canonical(vB)

	case "~":
		// Tilde: same major.minor, >= patch
		return semver.MajorMinor(vV) == semver.MajorMinor(vB) && semver.Compare(vV, vB) >= 0

	case ">=":
		// Greater than or equal: same major version, >= base
		return semver.Compare(vV, vB) >= 0

	case ">":
		// Greater than: same major version, > base
		return semver.Compare(vV, vB) > 0

	case "exact":
		return semver.Canonical(vV) == semver.Canonical(vB)

	default:
		return false
	}
}

// FetchPackageMetadata returns the packument of the package if no version is set.
// Otherwise the metadata of that version - taken from the packument, therefore no extra request is needed.
// The returned response is shared through the cache and must not be modified.
func (resolver *NPMResolver) FetchPackageMetadata(purl packageurl.PackageURL) (*NPMResponse, error) {
	packument, err := resolver.fetchPackument(buildFullPackageName(purl))
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %w", purl.ToString(), err)
	}

	if purl.Version == "" {
		return packument, nil
	}

	version := strings.Trim(purl.Version, "/")
	versionData, ok := packument.Versions[version]
	if !ok {
		return nil, fmt.Errorf("%w: version %s not found for %s", shared.ErrFixedVersionResolutionUnsupported, version, packument.Name)
	}

	return &NPMResponse{
		Name:                 packument.Name,
		Versions:             map[string]VersionData{version: versionData},
		Dependencies:         versionData.Dependencies,
		DevDependencies:      versionData.DevDependencies,
		PeerDependencies:     versionData.PeerDependencies,
		OptionalDependencies: versionData.OptionalDependencies,
	}, nil
}

// fetchPackument returns the cached packument or fetches it - concurrent fetches of the same package share one request
func (resolver *NPMResolver) fetchPackument(fullName string) (*NPMResponse, error) {
	if packument, ok := resolver.packuments.Get(fullName); ok {
		if packument == nil {
			return nil, npmPackageNotFound(fullName)
		}
		return packument, nil
	}

	res, err, _ := resolver.inflight.Do(fullName, func() (any, error) {
		packument, err := getNPMPackument(fullName)
		if errors.Is(err, errNPMPackageNotFound) {
			// unpublished packages (e.g. the project itself or private packages) are cached as nil
			resolver.packuments.Add(fullName, nil)
			return nil, npmPackageNotFound(fullName)
		}
		if err != nil {
			return nil, err
		}
		resolver.packuments.Add(fullName, packument)
		return packument, nil
	})
	if err != nil {
		return nil, err
	}
	return res.(*NPMResponse), nil
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
		return nil, fmt.Errorf("%w: invalid current version format: %s", shared.ErrFixedVersionResolutionUnsupported, currentVersion)
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
		return semver.Compare("v"+recommended[i], "v"+recommended[j]) > 0
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

func (resolver *NPMResolver) FindDependencyVersionInMeta(depMeta *NPMResponse, pkgName string) (VersionConstraint, bool) {
	for _, depType := range resolver.getAllDependencyMaps(depMeta) {
		if version, ok := depType[pkgName]; ok {
			return VersionConstraint(version), true
		}
	}
	return "", false
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
		return "", fmt.Errorf("%w: invalid semver in spec: %s", shared.ErrFixedVersionResolutionUnsupported, versionConstraint)
	}

	// For exact version, simply return the requested version; equality with currentVersion is allowed
	if rangeType == "exact" {
		if baseVersion == currentVersion {
			return "", fmt.Errorf("%w: exact version %s is same as current version, no upgrade possible", shared.ErrNoFixedVersionAvailable, baseVersion)
		}
		return baseVersion, nil
	}

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

		matches := false

		switch rangeType {
		case "^", "~", ">=", ">":
			matches = matchesVersionConstraint(rangeType, v, baseVersion)
		case "||":
			for _, orSpec := range baseVersions {
				orRangeType, orBaseVersion := resolver.ParseVersionConstraint(orSpec)

				// Normalize incomplete semver versions (e.g., "14.0" -> "14.0.0", "14" -> "14.0.0")
				orBaseVersionNormalized := normalizeVersion(orBaseVersion)

				if !semver.IsValid("v" + orBaseVersionNormalized) {
					continue // Skip invalid specs after normalization
				}

				if matchesVersionConstraint(orRangeType, v, orBaseVersionNormalized) {
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
		return "", fmt.Errorf("%w: no versions match spec %s", shared.ErrNoFixedVersionAvailable, versionConstraint)
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

var errNPMPackageNotFound = errors.New("npm package not found")

func npmPackageNotFound(fullName string) error {
	return fmt.Errorf("%w: package %s is not published on the npm registry", shared.ErrFixedVersionResolutionUnsupported, fullName)
}

// getNPMPackument fetches the abbreviated packument (all versions with their dependencies) of a package.
// fullName includes the scope for scoped packages, e.g. @babel/core
func getNPMPackument(fullName string) (*NPMResponse, error) {
	// the request is shared between all callers waiting on the same package (singleflight),
	// so it must not be tied to a single caller's context - bound it with a timeout instead
	ctx, cancel := context.WithTimeout(context.Background(), npmRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.npmjs.org/"+url.PathEscape(fullName), nil)
	if err != nil {
		return nil, err
	}
	// the abbreviated metadata is a fraction of the full packument but still contains the dependencies of every version
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")

	resp, err := utils.EgressClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errNPMPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data for %s: %s", fullName, resp.Status)
	}

	var packument NPMResponse
	if err := json.NewDecoder(resp.Body).Decode(&packument); err != nil {
		return nil, fmt.Errorf("error decoding JSON for %s: %w", fullName, err)
	}
	return &packument, nil
}
