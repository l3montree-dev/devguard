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

package dependencyfirewall

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"golang.org/x/sync/errgroup"
	"pault.ag/go/debian/control"
	"pault.ag/go/debian/version"
)

const debReplacementConcurrency = 10

type debReplacement struct {
	version   string
	firstSeen time.Time
	found     bool
}

type debCandidate struct {
	entry  shared.MetasnapEntry
	parsed version.Version
}

func (d *DebDependencyProxyController) checkDebPackages(configs DependencyProxyConfigs, registryConfig dtos.DebianRegistryConfig, suite string, packages []shared.DebPackage) map[int]string {
	result := make(map[int]string)
	for i, pkg := range packages {
		releasedAt := pkg.ReleasedAt
		if releasedAt.IsZero() {
			releasedAt = time.Now()
		}
		if notAllowed, reason := d.checkDebPackage(configs, registryConfig, suite, pkg.Paragraph.Values["Package"], pkg.Paragraph.Values["Version"], releasedAt); notAllowed {
			result[i] = reason
		}
	}
	return result
}

func debSourceKey(pkg control.Paragraph) string {
	source := pkg.Values["Source"]
	if source == "" {
		return pkg.Values["Package"] + "@" + pkg.Values["Version"]
	}

	name, rest, found := strings.Cut(source, " (")
	if found {
		return name + "@" + strings.TrimSuffix(rest, ")")
	}
	return name + "@" + pkg.Values["Version"]
}

func groupDebPackages(packages []shared.DebPackage, blocked map[int]string) map[string][]int {
	all := make(map[string][]int)
	for i, pkg := range packages {
		key := debSourceKey(pkg.Paragraph)
		all[key] = append(all[key], i)
	}

	groups := make(map[string][]int)
	for i := range blocked {
		key := debSourceKey(packages[i].Paragraph)
		groups[key] = all[key]
	}
	return groups
}

func (d *DebDependencyProxyController) checkDebPackage(configs DependencyProxyConfigs, registryConfig dtos.DebianRegistryConfig, suite, name, pkgVersion string, releasedAt time.Time) (bool, string) {
	celPkg := newPackage(deb, registryConfig.GetURL(), "debian/"+name, pkgVersion, releasedAt)
	celPkg.Suite = suite
	return d.CheckNotAllowedPackage(celPkg, configs)
}

func (d *DebDependencyProxyController) findDebReplacements(ctx context.Context, configs DependencyProxyConfigs, registryConfig dtos.DebianRegistryConfig, archive, suite string, packages []shared.DebPackage, groups map[string][]int) map[string]debReplacement {
	var mu sync.Mutex
	result := make(map[string]debReplacement, len(groups))
	var group errgroup.Group
	group.SetLimit(debReplacementConcurrency)
	for key, indices := range groups {
		group.Go(func() error {
			replacement := d.findDebReplacement(ctx, configs, registryConfig, archive, suite, packages, indices)
			mu.Lock()
			defer mu.Unlock()
			result[key] = replacement
			return nil
		})
	}
	_ = group.Wait()
	return result
}

func (d *DebDependencyProxyController) findDebReplacement(ctx context.Context, configs DependencyProxyConfigs, registryConfig dtos.DebianRegistryConfig, archive, suite string, packages []shared.DebPackage, indices []int) debReplacement {
	rep := packages[indices[0]].Paragraph
	entries, err := d.debReleaseTimeService.FetchMetasnap(ctx, archive, rep.Values["Package"], rep.Values["Architecture"])
	if err != nil {
		return debReplacement{}
	}

	current, err := version.Parse(rep.Values["Version"])
	if err != nil {
		return debReplacement{}
	}

	var candidates []debCandidate
	for _, entry := range entries {
		if entry.Suite != suite {
			continue
		}
		parsedCandidate, err := version.Parse(entry.Version)
		if err != nil || version.Compare(parsedCandidate, current) > 0 {
			continue
		}
		candidates = append(candidates, debCandidate{entry: entry, parsed: parsedCandidate})
	}

	sort.Slice(candidates, func(a, b int) bool {
		return version.Compare(candidates[a].parsed, candidates[b].parsed) > 0
	})

	for _, candidate := range candidates {
		if d.debGroupAllowed(configs, registryConfig, suite, packages, indices, candidate.entry) {
			return debReplacement{version: candidate.entry.Version, firstSeen: candidate.entry.FirstSeen, found: true}
		}
	}
	return debReplacement{}
}

func (d *DebDependencyProxyController) debGroupAllowed(configs DependencyProxyConfigs, registryConfig dtos.DebianRegistryConfig, suite string, packages []shared.DebPackage, indices []int, entry shared.MetasnapEntry) bool {
	for _, i := range indices {
		if notAllowed, _ := d.checkDebPackage(configs, registryConfig, suite, packages[i].Paragraph.Values["Package"], entry.Version, entry.FirstSeen); notAllowed {
			return false
		}
	}
	return true
}
