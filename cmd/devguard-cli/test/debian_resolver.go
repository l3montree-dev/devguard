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
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/ulikunitz/xz"
	"pault.ag/go/debian/control"
	"pault.ag/go/debian/dependency"
	"pault.ag/go/debian/version"
)

type DebianResolver struct{}

var distroToSuite = map[string]string{
	"debian-12":   "bookworm",
	"debian-12.8": "bookworm",
	"debian-11":   "bullseye",
	"debian-11.9": "bullseye",
	"debian-13":   "trixie",
	"debian-sid":  "sid",
	"":            "trixie", //some purls dont contain distros but they are implying latest, so trixie, if there is a newer version in the future, this will need to be updated to the newer suite
}

var debianConstraintRegex = regexp.MustCompile(`^(>>|>=|<<|<=|=)\s*(.+)$`)

func (d *DebianResolver) extractSuiteAndArch(purl packageurl.PackageURL) (suite, arch string, err error) {
	// Extract from qualifiers
	arch = purl.Qualifiers.Map()["arch"]
	distro := purl.Qualifiers.Map()["distro"]

	if arch == "" {
		return "", "", fmt.Errorf("missing required 'arch' qualifier in PURL: %s", purl.String())
	}
	if mappedSuite, ok := distroToSuite[distro]; ok {
		suite = mappedSuite
	} else {
		// Try extracting major version (e.g., "debian-12.8" -> "debian-12")
		parts := strings.Split(distro, ".")
		if len(parts) > 0 {
			if mappedSuite, ok := distroToSuite[parts[0]]; ok {
				suite = mappedSuite
			}
		}
	}

	if suite == "" {
		return "", "", fmt.Errorf("unknown distro qualifier '%s' in PURL: %s", distro, purl.String())
	}

	return suite, arch, nil
}

func (resolver *DebianResolver) ParseVersionConstraint(spec string) (rangeType string, baseVersion string) {
	spec = strings.TrimSpace(spec)

	var extracted string
	if strings.HasPrefix(spec, ">>") {
		rangeType = ">>"
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, ">>"))
	} else if strings.HasPrefix(spec, ">=") {
		rangeType = ">="
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, ">="))
	} else if strings.HasPrefix(spec, "<<") {
		rangeType = "<<"
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, "<<"))
	} else if strings.HasPrefix(spec, "<=") {
		rangeType = "<="
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, "<="))
	} else if strings.HasPrefix(spec, "=") {
		rangeType = "="
		extracted = strings.TrimSpace(strings.TrimPrefix(spec, "="))
	} else {
		rangeType = "exact"
		extracted = spec
	}

	return rangeType, extracted
}

var _ Resolver[DebianResponse] = &DebianResolver{}

func (d *DebianResolver) FetchPackageMetadata(purl packageurl.PackageURL) (DebianResponse, error) {
	pkgName := purl.Name

	suite, arch, err := d.extractSuiteAndArch(purl)
	if err != nil {
		return DebianResponse{}, err
	}

	return d.fetchVersionMetadata(pkgName, purl.Version, suite, arch)
}

// fetchVersionMetadata fetches dependencies for a specific package version
func (d *DebianResolver) fetchVersionMetadata(pkgName, pkgVersion, suite, arch string) (DebianResponse, error) {
	// Fetch from Packages.xz for the specified suite
	url := "https://deb.debian.org/debian/dists/" + suite + "/main/binary-" + arch + "/Packages.xz"

	resp, err := httpClient.Get(url)
	if err != nil {
		return DebianResponse{}, fmt.Errorf("failed to fetch Packages.xz: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return DebianResponse{}, fmt.Errorf("Packages.xz returned %d", resp.StatusCode)
	}

	// Decompress xz
	xzReader, err := xz.NewReader(resp.Body)
	if err != nil {
		return DebianResponse{}, fmt.Errorf("failed to create xz reader: %w", err)
	}

	// Parse Debian control format with pault.ag

	paragraphReader, err := control.NewParagraphReader(xzReader, nil)
	if err != nil {
		return DebianResponse{}, fmt.Errorf("failed to create paragraph reader: %w", err)
	}

	for {
		pkg, err := paragraphReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return DebianResponse{}, fmt.Errorf("failed to read control paragraph: %w", err)
		}

		name := pkg.Values["Package"]
		ver := pkg.Values["Version"]

		if name == pkgName && (pkgVersion == "" || debianVersionsMatch(ver, pkgVersion)) {
			deps := d.parseDependencies(pkg.Values["Depends"])
			return DebianResponse{
				PackageName:  pkgName,
				Versions:     []string{ver}, // use the actual version from Packages.xz (may include epoch)
				Dependencies: deps,
				RawMetadata:  *pkg,
			}, nil
		}
	}

	if pkgVersion == "" {
		return DebianResponse{}, fmt.Errorf("package %s not found in %s/%s", pkgName, suite, arch)
	}
	return DebianResponse{}, fmt.Errorf("package %s@%s not found in %s/%s", pkgName, pkgVersion, suite, arch)
}

// Returns a map of package -> version constraint
func (d *DebianResolver) parseDependencies(depString string) map[string]string {
	if depString == "" {
		return make(map[string]string)
	}

	deps := make(map[string]string)

	rel, err := dependency.Parse(depString)
	if err != nil {
		fmt.Printf("Warning: failed to parse dependencies '%s': %v\n", depString, err)
		return deps
	}

	if rel == nil {
		return deps
	}

	// example:  Depends: libc6 (>= 2.40), libcurl3t64-gnutls (>= 7.16.2), zlib1g, will turn this into a map [string]string

	for _, possibility := range rel.Relations {
		// Take first alternative (MVP approach)
		if len(possibility.Possibilities) > 0 {
			dep := possibility.Possibilities[0]
			pkgName := dep.Name

			var constraint string
			if dep.Version != nil {
				constraint = dep.Version.Operator + " " + dep.Version.Number
			}

			deps[pkgName] = constraint
		}
	}

	return deps
}

// GetUpgradeCandidates returns newer versions than currentVersion (upgrade candidates)
func (d *DebianResolver) GetUpgradeCandidates(allVersionsMeta DebianResponse, currentVersion string) ([]string, error) {
	if len(allVersionsMeta.Versions) == 0 {
		return nil, fmt.Errorf("no versions available")
	}

	currentVer, err := version.Parse(currentVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid current version '%s': %w", currentVersion, err)
	}

	var recommended []string
	for _, ver := range allVersionsMeta.Versions {
		parsedVer, err := version.Parse(ver)
		if err != nil {
			continue // skip invalid versions
		}

		// Include versions >= currentVersion
		if version.Compare(parsedVer, currentVer) >= 0 {
			recommended = append(recommended, ver)
		}
	}

	return recommended, nil
}

func (d *DebianResolver) FindDependencyVersionInMeta(depMeta DebianResponse, pkgName string) VersionConstraint {
	constraint, exists := depMeta.Dependencies[pkgName]
	if !exists {
		return ""
	}
	return VersionConstraint(constraint)
}

func (d *DebianResolver) ResolveBestVersion(allVersionsMeta DebianResponse, versionConstraint VersionConstraint, currentVersion string) (string, error) {
	constraint := string(versionConstraint)

	// If no constraint, return newest version
	if constraint == "" {
		if len(allVersionsMeta.Versions) > 0 {
			return allVersionsMeta.Versions[0], nil
		}
		return "", fmt.Errorf("no versions available")
	}

	// Parse constraint: ">> 1.2.3", ">= 1.2.3", "<< 2.0", "= 1.2.3", etc.
	operator, constraintVer, err := parseDebianConstraint(constraint)
	if err != nil {
		return "", fmt.Errorf("failed to parse constraint '%s': %w", constraint, err)
	}

	targetVer, err := version.Parse(constraintVer)
	if err != nil {
		return "", fmt.Errorf("invalid constraint version '%s': %w", constraintVer, err)
	}

	// filter
	var candidates []string
	for _, ver := range allVersionsMeta.Versions {
		parsedVer, err := version.Parse(ver)
		if err != nil {
			continue
		}

		cmp := version.Compare(parsedVer, targetVer)
		match := false

		switch operator {
		case ">>":
			match = cmp > 0
		case ">=":
			match = cmp >= 0
		case "<<":
			match = cmp < 0
		case "<=":
			match = cmp <= 0
		case "=":
			match = cmp == 0
		}

		if match {
			candidates = append(candidates, ver)
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("no version matches constraint '%s'", constraint)
	}

	type parsedVer struct {
		str string
		ver version.Version
	}
	parsedVersions := make([]parsedVer, len(candidates))
	for i, ver := range candidates {
		pv, _ := version.Parse(ver) // Already validated during filtering
		parsedVersions[i] = parsedVer{ver, pv}
	}

	// Sort candidates and return the highest (newest) version
	sort.Slice(parsedVersions, func(i, j int) bool {
		return version.Compare(parsedVersions[i].ver, parsedVersions[j].ver) > 0
	})

	return parsedVersions[0].str, nil
}

func (d *DebianResolver) CheckIfVulnerabilityIsFixed(vulnVersion string, fixedVersion string) bool {
	vVuln, err := version.Parse(vulnVersion)
	if err != nil {
		return false
	}

	vFixed, err := version.Parse(fixedVersion)
	if err != nil {
		return false
	}

	// Vulnerability is fixed if vulnVersion >= fixedVersion
	return version.Compare(vVuln, vFixed) >= 0
}


func parseDebianConstraint(constraint string) (string, string, error) {
	constraint = strings.TrimSpace(constraint)

	// Match Debian operators: >>, >=, <<, <=, =
	matches := debianConstraintRegex.FindStringSubmatch(constraint)

	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid constraint format: %s", constraint)
	}

	return matches[1], strings.TrimSpace(matches[2]), nil
}

// debianVersionsMatch compares two Debian version strings, accounting for epoch prefix differences.
// PURLs from SBOMs often omit the epoch prefix (e.g., "2.47.3-0+deb13u1"),
// while Packages.xz includes it (e.g., "1:2.47.3-0+deb13u1").
func debianVersionsMatch(packagesXzVer, purlVer string) bool {

	if packagesXzVer == purlVer {
		return true
	}
	if idx := strings.Index(packagesXzVer, ":"); idx != -1 {
		withoutEpoch := packagesXzVer[idx+1:]
		if withoutEpoch == purlVer {
			return true
		}
	}

	if idx := strings.Index(purlVer, ":"); idx != -1 {
		withoutEpoch := purlVer[idx+1:]
		if packagesXzVer == withoutEpoch {
			return true
		}
	}

	return false
}
