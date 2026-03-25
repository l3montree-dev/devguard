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
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/package-url/packageurl-go"
	"github.com/ulikunitz/xz"
	"pault.ag/go/debian/control"
	"pault.ag/go/debian/dependency"
	"pault.ag/go/debian/version"
)

type distroArch struct {
	distro string
	arch   string
}

// debianEntry holds offsets into packageIndex.data for name, version, and depends.
type debianEntry struct {
	nameOff    uint32
	nameLen    uint16
	versionOff uint32
	versionLen uint16
	dependsOff uint32
	dependsLen uint32
}

// nameRange is a (offset, length) pointer into a []byte arena.
type nameRange struct {
	off uint32
	len uint16
}

// packageIndex is a compact, arena-backed package list sorted by name.
// data is a single backing buffer holding, in order:
//
//	pass-1: [name₀][ver₀][name₁][ver₁]…  (all entry names then all versions interleaved)
//	pass-2: [deps₀][deps₁]…              (tokenised depends blobs appended after)
//
// depDict/depRanges is a sorted uint16-token dictionary of dep-field package names.
// Binary dep format per record: [uint16LE token][constraint bytes]['\n']
type packageIndex struct {
	entries   []debianEntry
	data      []byte      // names + versions + tokenised deps in one allocation
	depDict   []byte      // dep-name strings concatenated
	depRanges []nameRange // depRanges[token] → offset/len in depDict
}

func (idx *packageIndex) nameOf(e debianEntry) string {
	return unsafe.String(&idx.data[e.nameOff], int(e.nameLen))
}

func (idx *packageIndex) versionOf(e debianEntry) string {
	return unsafe.String(&idx.data[e.versionOff], int(e.versionLen))
}

// findByName returns all entries for the given package name via binary search.
func (idx *packageIndex) findByName(name string) []debianEntry {
	lo := sort.Search(len(idx.entries), func(i int) bool {
		return idx.nameOf(idx.entries[i]) >= name
	})
	if lo >= len(idx.entries) || idx.nameOf(idx.entries[lo]) != name {
		return nil
	}
	hi := lo + 1
	for hi < len(idx.entries) && idx.nameOf(idx.entries[hi]) == name {
		hi++
	}
	return idx.entries[lo:hi]
}

// findDepToken returns the uint16 token for pkgName, or -1 if not in the dictionary.
func (idx *packageIndex) findDepToken(name string) int {
	lo := sort.Search(len(idx.depRanges), func(i int) bool {
		n := idx.depRanges[i]
		return unsafe.String(&idx.depDict[n.off], int(n.len)) >= name
	})
	if lo >= len(idx.depRanges) {
		return -1
	}
	n := idx.depRanges[lo]
	if unsafe.String(&idx.depDict[n.off], int(n.len)) != name {
		return -1
	}
	return lo
}

// lookupDepToken scans the binary dep records for entry e and returns the constraint
// string for pkgName (e.g. ">= 2.36", or "" if unconstrained), or ("", false) if absent.
func (idx *packageIndex) lookupDepToken(e debianEntry, pkgName string) (string, bool) {
	token := idx.findDepToken(pkgName)
	if token < 0 {
		return "", false
	}
	want := uint16(token)
	data := idx.data[e.dependsOff : e.dependsOff+e.dependsLen]
	for len(data) >= 3 { // 2-byte token + at least '\n'
		tok := uint16(data[0]) | uint16(data[1])<<8
		data = data[2:]
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			break
		}
		constraint := string(data[:nl])
		data = data[nl+1:]
		if tok == want {
			return constraint, true
		}
	}
	return "", false
}

type DebianResolver struct {
	index      map[distroArch]*packageIndex
	timestamps map[distroArch]time.Time
}

var distroToSuite = map[string]string{
	"debian-12":   "bookworm",
	"debian-12.8": "bookworm",
	"debian-11":   "bullseye",
	"debian-11.9": "bullseye",
	"debian-13":   "trixie",
	"debian-sid":  "sid",
	"":            "trixie", //some purls dont contain distros but they are implying latest, so trixie, if there is a newer version in the future, this will need to be updated to the newer suite
}

func NewDebianResolver() *DebianResolver {
	d := DebianResolver{
		index:      make(map[distroArch]*packageIndex),
		timestamps: make(map[distroArch]time.Time),
	}
	return &d
}

func (d *DebianResolver) getPackagesXZ(suite, arch string) (*packageIndex, error) {
	key := distroArch{suite, arch}
	if idx, exists := d.index[key]; exists {
		// check if older than 12h
		lastTime := d.timestamps[key]
		if time.Since(lastTime) < 12*time.Hour {
			return idx, nil
		}
	}

	url := "https://deb.debian.org/debian/dists/" + suite + "/main/binary-" + arch + "/Packages.xz"
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Packages.xz: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Packages.xz returned %d", resp.StatusCode)
	}

	xzReader, err := xz.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create xz reader: %w", err)
	}

	paragraphReader, err := control.NewParagraphReader(xzReader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create paragraph reader: %w", err)
	}

	idx, err := buildPackageIndex(paragraphReader)
	if err != nil {
		return nil, fmt.Errorf("failed to build package index: %w", err)
	}
	d.index[key] = idx
	d.timestamps[key] = time.Now()
	return idx, nil
}

// buildPackageIndex parses all paragraphs and builds a compact arena-backed index.
// Dep names are tokenised to uint16 so each occurrence costs 2 bytes instead of ~10.
func buildPackageIndex(paragraphReader *control.ParagraphReader) (*packageIndex, error) {
	type raw struct{ name, version, depends string }
	var rows []raw
	var arenaSize int

	for {
		pkg, err := paragraphReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read control paragraph: %w", err)
		}
		name := pkg.Values["Package"]
		ver := pkg.Values["Version"]
		deps := parseDependencies(pkg.Values["Depends"])
		arenaSize += len(name) + len(ver)
		rows = append(rows, raw{name, ver, deps})
	}

	// Sort by name so findByName can binary-search.
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	// --- Build dep-name token dictionary (uint16, dep-field names only) ---
	depNameSet := make(map[string]uint16, 40000)
	for _, r := range rows {
		s := r.depends
		for len(s) > 0 {
			line, rest, _ := strings.Cut(s, "\n")
			s = rest
			name, _, _ := strings.Cut(line, " ")
			if name != "" {
				depNameSet[name] = 0
			}
		}
	}
	uniqueDepNames := make([]string, 0, len(depNameSet))
	for name := range depNameSet {
		uniqueDepNames = append(uniqueDepNames, name)
	}
	sort.Strings(uniqueDepNames)

	depDict := make([]byte, 0, len(depNameSet)*10)
	depRanges := make([]nameRange, len(uniqueDepNames))
	for i, name := range uniqueDepNames {
		depRanges[i] = nameRange{off: uint32(len(depDict)), len: uint16(len(name))}
		depDict = append(depDict, name...)
		depNameSet[name] = uint16(i)
	}

	// --- Single data buffer: pass-1 names+versions, pass-2 tokenised deps ---
	var depsCap int
	for _, r := range rows {
		s := r.depends
		for len(s) > 0 {
			line, rest, _ := strings.Cut(s, "\n")
			s = rest
			if line == "" {
				continue
			}
			_, constraint, _ := strings.Cut(line, " ")
			depsCap += 2 + len(constraint) + 1
		}
	}
	data := make([]byte, 0, arenaSize+depsCap)
	entries := make([]debianEntry, len(rows))

	// Pass 1: names and versions
	for i, r := range rows {
		nameOff := uint32(len(data))
		data = append(data, r.name...)
		verOff := uint32(len(data))
		data = append(data, r.version...)
		entries[i].nameOff = nameOff
		entries[i].nameLen = uint16(len(r.name))
		entries[i].versionOff = verOff
		entries[i].versionLen = uint16(len(r.version))
	}

	// Pass 2: tokenised dep blobs
	for i, r := range rows {
		depsOff := uint32(len(data))
		s := r.depends
		for len(s) > 0 {
			line, rest, _ := strings.Cut(s, "\n")
			s = rest
			if line == "" {
				continue
			}
			name, constraint, _ := strings.Cut(line, " ")
			tok := depNameSet[name]
			data = append(data, byte(tok), byte(tok>>8))
			data = append(data, constraint...)
			data = append(data, '\n')
		}
		entries[i].dependsOff = depsOff
		entries[i].dependsLen = uint32(len(data)) - depsOff
	}

	return &packageIndex{
		entries:   entries,
		data:      data,
		depDict:   depDict,
		depRanges: depRanges,
	}, nil
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

func (d *DebianResolver) ParseVersionConstraint(spec string) (rangeType string, baseVersion string) {
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
	return d.parseParagraphs(pkgName, pkgVersion, suite, arch)
}

// parseParagraphs iterates through all control paragraphs and collects matching packages
func (d *DebianResolver) parseParagraphs(pkgName, pkgVersion, suite, arch string) (DebianResponse, error) {
	var allVersions []string
	var targetEntry debianEntry
	var targetVersion string
	targetFound := false

	idx, err := d.getPackagesXZ(suite, arch)
	if err != nil {
		return DebianResponse{}, fmt.Errorf("failed to get Packages.xz data: %w", err)
	}

	entries := idx.findByName(pkgName)
	if len(entries) == 0 {
		return DebianResponse{}, fmt.Errorf("package %s not found in suite %s for arch %s", pkgName, suite, arch)
	}

	for _, e := range entries {
		ver := idx.versionOf(e)
		allVersions = append(allVersions, ver)

		if pkgVersion != "" && debianVersionsMatch(ver, pkgVersion) {
			targetEntry = e
			targetVersion = ver
			targetFound = true
			break
		}
	}

	if pkgVersion != "" {
		if !targetFound {
			return DebianResponse{}, fmt.Errorf("package %s@%s not found in %s", pkgName, pkgVersion, "suite")
		}
		return DebianResponse{
			PackageName: pkgName,
			Versions:    []string{targetVersion},
			depIdx:      idx,
			depEntry:    targetEntry,
		}, nil
	}

	if len(allVersions) == 0 {
		return DebianResponse{}, fmt.Errorf("package %s not found in %s", pkgName, "suite")
	}

	return DebianResponse{
		PackageName: pkgName,
		Versions:    allVersions,
	}, nil
}

// parseDependencies encodes a Debian Depends field as newline-separated lines.
// Each line is "pkgname constraint" or just "pkgname" when unconstrained.
// Example: "libc6 >= 2.36\nzlib1g\ncurl >= 7.0"
func parseDependencies(depString string) string {
	if depString == "" {
		return ""
	}

	rel, err := dependency.Parse(depString)
	if err != nil || rel == nil {
		return ""
	}

	var b strings.Builder
	for _, possibility := range rel.Relations {
		if len(possibility.Possibilities) == 0 {
			continue
		}
		dep := possibility.Possibilities[0]
		b.WriteString(dep.Name)
		if dep.Version != nil {
			b.WriteByte(' ')
			b.WriteString(dep.Version.Operator)
			b.WriteByte(' ')
			b.WriteString(dep.Version.Number)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// lookupDependency finds a package in a flat Dependencies string.
func lookupDependency(depends, pkgName string) (string, bool) {
	s := depends
	for len(s) > 0 {
		line, rest, _ := strings.Cut(s, "\n")
		s = rest
		name, constraint, _ := strings.Cut(line, " ")
		if name == pkgName {
			return constraint, true
		}
	}
	return "", false
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

	// Sort by version (highest first)
	type versionPair struct {
		str string
		ver version.Version
	}
	versionPairs := make([]versionPair, len(recommended))
	for i, ver := range recommended {
		pv, _ := version.Parse(ver) // Already validated during filtering
		versionPairs[i] = versionPair{ver, pv}
	}

	sort.Slice(versionPairs, func(i, j int) bool {
		return version.Compare(versionPairs[i].ver, versionPairs[j].ver) > 0
	})

	sortedRecommended := make([]string, len(versionPairs))
	for i, vp := range versionPairs {
		sortedRecommended[i] = vp.str
	}

	return sortedRecommended, nil
}

func (d *DebianResolver) FindDependencyVersionInMeta(depMeta DebianResponse, pkgName string) (VersionConstraint, bool) {
	if depMeta.depIdx != nil {
		constraint, ok := depMeta.depIdx.lookupDepToken(depMeta.depEntry, pkgName)
		return VersionConstraint(constraint), ok
	}
	constraint, exists := lookupDependency(depMeta.Dependencies, pkgName)
	return VersionConstraint(constraint), exists
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
// Uses pault.ag/go/debian/version for proper Debian version comparison.
func debianVersionsMatch(packagesXzVer, purlVer string) bool {
	// Parse with pault.ag library which handles Debian versioning correctly
	pv, err1 := version.Parse(packagesXzVer)
	v, err2 := version.Parse(purlVer)

	if err1 != nil || err2 != nil {
		return packagesXzVer == purlVer
	}

	// version.Compare() handles epochs, +deb12u9 vs +deb12u10, +b1, +dfsg correctly
	return version.Compare(pv, v) == 0
}
