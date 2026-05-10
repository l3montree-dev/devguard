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
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// CacheStats describes aggregate storage usage for a slice of the dependency
// proxy on-disk cache (one ecosystem, the OCI manifest/blob split, or the
// overall total).
type CacheStats struct {
	SizeBytes   int64      `json:"sizeBytes"`
	Entries     int        `json:"entries"`
	OldestEntry *time.Time `json:"oldestEntry,omitempty"`
	NewestEntry *time.Time `json:"newestEntry,omitempty"`
}

// OCISubStats further splits the OCI cache into manifests and blobs.
type OCISubStats struct {
	Manifests CacheStats `json:"manifests"`
	Blobs     CacheStats `json:"blobs"`
}

// CacheStatsResponse is the JSON returned by GetCacheStats.
type CacheStatsResponse struct {
	CacheDir     string                `json:"cacheDir"`
	TotalSize    int64                 `json:"totalSizeBytes"`
	TotalEntries int                   `json:"totalEntries"`
	OldestEntry  *time.Time            `json:"oldestEntry,omitempty"`
	NewestEntry  *time.Time            `json:"newestEntry,omitempty"`
	ByEcosystem  map[string]CacheStats `json:"byEcosystem"`
	OCIBreakdown OCISubStats           `json:"ociBreakdown"`
}

// companionSuffixes are sidecar files written next to a cached payload. They
// count toward disk usage but not toward entry counts.
var companionSuffixes = []string{".sha256", ".releasetime", ".contenttype", ".digest"}

func isCompanionFile(name string) bool {
	for _, s := range companionSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// GetCacheStats walks the on-disk dependency proxy cache and returns aggregate
// storage statistics, both overall and broken down per ecosystem. The OCI
// subtree is split further into manifests vs blobs.
func (d *DependencyProxyController) GetCacheStats(ctx shared.Context) error {
	resp, err := d.CollectCacheStats()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to read cache stats: %v", err))
	}
	return ctx.JSON(http.StatusOK, resp)
}

func (d *DependencyProxyController) CollectCacheStats() (CacheStatsResponse, error) {
	resp := CacheStatsResponse{
		CacheDir:    d.cacheDir,
		ByEcosystem: map[string]CacheStats{},
	}

	if _, err := os.Stat(d.cacheDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return resp, nil
		}
		return resp, err
	}

	ecoStats := map[string]*CacheStats{}
	total := &CacheStats{}
	ociMan := &CacheStats{}
	ociBlob := &CacheStats{}

	walkErr := filepath.Walk(d.cacheDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, relErr := filepath.Rel(d.cacheDir, path)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		parts := strings.SplitN(relSlash, "/", 2)
		if len(parts) < 2 {
			// File directly under cache root — not produced by the proxy code paths,
			// but keep accounting honest by including its size in the total.
			total.SizeBytes += info.Size()
			updateTimes(total, info.ModTime())
			return nil
		}
		eco := parts[0]
		stats, ok := ecoStats[eco]
		if !ok {
			stats = &CacheStats{}
			ecoStats[eco] = stats
		}

		size := info.Size()
		mod := info.ModTime()
		companion := isCompanionFile(info.Name())

		stats.SizeBytes += size
		updateTimes(stats, mod)
		if !companion {
			stats.Entries++
		}

		total.SizeBytes += size
		updateTimes(total, mod)
		if !companion {
			total.Entries++
		}

		if eco == "oci" {
			switch {
			case strings.Contains(relSlash, "/manifests/"):
				ociMan.SizeBytes += size
				updateTimes(ociMan, mod)
				if !companion {
					ociMan.Entries++
				}
			case strings.Contains(relSlash, "/blobs/"):
				ociBlob.SizeBytes += size
				updateTimes(ociBlob, mod)
				if !companion {
					ociBlob.Entries++
				}
			}
		}

		return nil
	})
	if walkErr != nil {
		return resp, walkErr
	}

	for eco, s := range ecoStats {
		resp.ByEcosystem[eco] = *s
	}
	resp.TotalSize = total.SizeBytes
	resp.TotalEntries = total.Entries
	resp.OldestEntry = total.OldestEntry
	resp.NewestEntry = total.NewestEntry
	resp.OCIBreakdown = OCISubStats{Manifests: *ociMan, Blobs: *ociBlob}

	return resp, nil
}

func updateTimes(s *CacheStats, mod time.Time) {
	if s.OldestEntry == nil || mod.Before(*s.OldestEntry) {
		t := mod
		s.OldestEntry = &t
	}
	if s.NewestEntry == nil || mod.After(*s.NewestEntry) {
		t := mod
		s.NewestEntry = &t
	}
}
