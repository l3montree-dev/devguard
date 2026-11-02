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

package services

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/errgroup"
	"pault.ag/go/debian/control"
)

const (
	metasnapURL         = "https://metasnap.debian.net/cgi-bin/api"
	metasnapConcurrency = 10
	metasnapCacheTTL    = time.Hour
	metasnapCacheSize   = 20_000
	debSnapshotAge      = 30 * 24 * time.Hour
)

func parseMetasnap(r io.Reader) ([]shared.MetasnapEntry, error) {
	scanner := bufio.NewScanner(r)
	var metasnapEntries []shared.MetasnapEntry

	for scanner.Scan() {
		line := scanner.Text()
		lineFields := strings.Fields(line)
		if len(lineFields) == 0 {
			continue
		}
		if len(lineFields) != 5 {
			return nil, fmt.Errorf("unexpected metasnap line: %s", line)
		}

		firstSeen, err := time.Parse(shared.MetasnapLayout, lineFields[3])
		if err != nil {
			return nil, fmt.Errorf("failed to parse time %q: %w", lineFields[3], err)
		}
		metasnapEntries = append(metasnapEntries, shared.MetasnapEntry{Version: lineFields[0], Suite: lineFields[1], FirstSeen: firstSeen})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}
	return metasnapEntries, nil
}

func (s DebReleaseTimeService) FetchMetasnap(ctx context.Context, archive, name, arch string) ([]shared.MetasnapEntry, error) {
	query := "archive=" + url.QueryEscape(archive) + "&pkg=" + url.QueryEscape(name) + "&arch=" + url.QueryEscape(arch)

	return s.metasnap.GetOrLoad(query, func() ([]shared.MetasnapEntry, error) {
		reader, err := utils.DoGetRequestWithContext(ctx, metasnapURL+"?"+query, &s.client)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch metasnap data: %w", err)
		}
		defer reader.Close()

		return parseMetasnap(reader)
	})
}

func metasnapFirstSeen(entries []shared.MetasnapEntry, version, suite string) (time.Time, bool) {
	for _, entry := range entries {
		if entry.Version == version && entry.Suite == suite {
			return entry.FirstSeen, true
		}
	}
	return time.Time{}, false
}

func (s DebReleaseTimeService) resolveReleasedAt(ctx context.Context, archive, suite, component, arch string, packages []control.Paragraph, previous []shared.DebPackage) ([]time.Time, error) {
	snapshotTime := time.Now().Add(-debSnapshotAge)

	_, snapshotPackages, err := s.LoadDebPackages(ctx, shared.SnapshotDebConfig(), shared.DebSnapshotPath(archive, snapshotTime), suite, component, arch)
	if err != nil {
		return nil, err
	}

	snapshotVersions := make(map[string]string, len(snapshotPackages))
	for _, pkg := range snapshotPackages {
		snapshotVersions[pkg.Values["Package"]] = pkg.Values["Version"]
	}

	known := make(map[string]time.Time, len(previous))
	for _, pkg := range previous {
		if !pkg.ReleasedAt.IsZero() {
			known[shared.DebPackageKey(pkg.Paragraph)] = pkg.ReleasedAt
		}
	}

	times := make([]time.Time, len(packages))
	var young []int
	for i, pkg := range packages {
		if releasedAt, ok := known[shared.DebPackageKey(pkg)]; ok {
			times[i] = releasedAt
			continue
		}
		if snapshotVersions[pkg.Values["Package"]] == pkg.Values["Version"] {
			times[i] = snapshotTime
			continue
		}
		young = append(young, i)
	}

	var group errgroup.Group
	group.SetLimit(metasnapConcurrency)
	for _, i := range young {
		group.Go(func() error {
			pkg := packages[i]
			entries, err := s.FetchMetasnap(ctx, archive, pkg.Values["Package"], pkg.Values["Architecture"])
			if err != nil {
				// slog.Warn("could not fetch metasnap data", "package", pkg.Values["Package"], "error", err)
				return nil
			}

			if firstSeen, found := metasnapFirstSeen(entries, pkg.Values["Version"], suite); found {
				times[i] = firstSeen
			}
			return nil
		})
	}
	_ = group.Wait()
	return times, nil
}
