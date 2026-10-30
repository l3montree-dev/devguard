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
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"pault.ag/go/debian/control"
)

func debSnapshotParagraph(pkg control.Paragraph, snapshotTime time.Time) control.Paragraph {
	values := maps.Clone(pkg.Values)
	values["Filename"] = shared.DebSnapshotPath("snapshot", snapshotTime) + "/" + pkg.Values["Filename"]
	return control.Paragraph{Values: values, Order: pkg.Order}
}

func (d *DebDependencyProxyController) loadDebSnapshotIndex(ctx context.Context, loaded map[time.Time]map[string]control.Paragraph, archive, suite, component, arch string, snapshotTime time.Time) (map[string]control.Paragraph, error) {
	if loaded[snapshotTime] != nil {
		return loaded[snapshotTime], nil
	}

	_, snapshotPackages, err := d.debReleaseTimeService.LoadDebPackages(ctx, shared.SnapshotDebConfig(), shared.DebSnapshotPath(archive, snapshotTime), suite, component, arch)
	if err != nil {
		return nil, err
	}

	packageMap := make(map[string]control.Paragraph)
	for _, pkg := range snapshotPackages {
		packageMap[pkg.Values["Package"]] = pkg
	}

	loaded[snapshotTime] = packageMap
	return packageMap, nil
}

func debGroupFromSnapshot(snapshot map[string]control.Paragraph, packages []shared.DebPackage, indices []int, snapshotTime time.Time) ([]control.Paragraph, error) {
	var resultList []control.Paragraph
	for _, index := range indices {
		name := packages[index].Paragraph.Values["Package"]
		oldEntry, found := snapshot[name]
		if !found {
			return nil, fmt.Errorf("%s missing in snapshot %s", name, snapshotTime.UTC().Format(shared.MetasnapLayout))
		}
		resultList = append(resultList, debSnapshotParagraph(oldEntry, snapshotTime))
	}
	return resultList, nil
}

func (d *DebDependencyProxyController) debGroupReplacement(ctx context.Context, loaded map[time.Time]map[string]control.Paragraph, archive, suite, component, arch string, packages []shared.DebPackage, indices []int, r debReplacement) ([]control.Paragraph, error) {
	snapshot, err := d.loadDebSnapshotIndex(ctx, loaded, archive, suite, component, arch, r.firstSeen)
	if err != nil {
		return nil, err
	}
	return debGroupFromSnapshot(snapshot, packages, indices, r.firstSeen)
}

func (d *DebDependencyProxyController) applyDebReplacements(ctx context.Context, archive, suite, component, arch string, packages []shared.DebPackage, groups map[string][]int, replacements map[string]debReplacement) []shared.DebPackage {
	result := slices.Clone(packages)
	remove := map[int]bool{}
	loaded := map[time.Time]map[string]control.Paragraph{}

	for key, indices := range groups {
		r := replacements[key]
		if r.found && r.version == packages[indices[0]].Paragraph.Values["Version"] {
			continue
		}

		var oldEntries []control.Paragraph
		var err error
		if r.found {
			oldEntries, err = d.debGroupReplacement(ctx, loaded, archive, suite, component, arch, packages, indices, r)
			if err != nil {
				slog.Warn("Could not replace blocked debian package, removing it", "group", key, "suite", suite, "error", err)
			}
		}
		if oldEntries == nil {
			for _, i := range indices {
				remove[i] = true
			}
			continue
		}

		for j, i := range indices {
			result[i] = shared.DebPackage{Paragraph: oldEntries[j], ReleasedAt: r.firstSeen}
		}
	}

	kept := make([]shared.DebPackage, 0, len(result))
	for i, pkg := range result {
		if !remove[i] {
			kept = append(kept, pkg)
		}
	}
	return kept
}
