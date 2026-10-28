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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"golang.org/x/sync/errgroup"
)

const (
	debIndexTTL      = 30 * time.Minute
	debIndexMaxBytes = 1 << 30
)

type debIndex struct {
	files map[string][]byte
	size  int
}

func (d *DebDependencyProxyController) getDebIndex(ctx context.Context, configs DependencyProxyConfigs, archive, suite string) (*debIndex, error) {
	key := configs.Secret.String() + "/" + configs.getRegistry(deb, shared.DebRegistry) + "/" + archive + "/" + suite
	return d.debIndexes.GetOrLoad(key, func() (*debIndex, error) {
		return d.buildDebIndex(context.WithoutCancel(ctx), configs, archive, suite)
	})
}

func (d *DebDependencyProxyController) loadDebPackageIndex(ctx context.Context, registry, archive, suite, component, arch string) (shared.DebPackageIndex, error) {
	debianIndex, err := d.debReleaseTimeService.Load(ctx, archive, suite, component, arch)
	if registry == shared.DebRegistry {
		return debianIndex, err
	}
	if err != nil && !shared.IsNotFound(err) {
		return shared.DebPackageIndex{}, err
	}

	release, packages, err := d.debReleaseTimeService.LoadDebPackages(ctx, registry, archive, suite, component, arch)
	if err != nil {
		return shared.DebPackageIndex{}, err
	}

	releaseTimes := make(map[string]time.Time, len(debianIndex.DebPackages))
	for _, pkg := range debianIndex.DebPackages {
		releaseTimes[shared.DebPackageKey(pkg.Paragraph)] = pkg.ReleasedAt
	}

	debPackages := make([]shared.DebPackage, len(packages))
	for i, pkg := range packages {
		debPackages[i] = shared.DebPackage{Paragraph: pkg, ReleasedAt: releaseTimes[shared.DebPackageKey(pkg)]}
	}
	return shared.DebPackageIndex{DebRelease: release, DebPackages: debPackages}, nil
}

func (d *DebDependencyProxyController) buildDebIndex(ctx context.Context, configs DependencyProxyConfigs, archive, suite string) (*debIndex, error) {
	start := time.Now()
	registry := configs.getRegistry(deb, shared.DebRegistry)

	var mu sync.Mutex
	var release shared.DebRelease
	files := make(map[string][]byte)
	var group errgroup.Group
	for _, component := range shared.DebComponents {
		for _, arch := range shared.DebArchitectures {
			group.Go(func() error {
				base, err := d.loadDebPackageIndex(ctx, registry, archive, suite, component, arch)
				if errors.Is(err, shared.ErrDebFileNotListed) {
					return nil
				}
				if err != nil {
					return err
				}
				blocked := d.checkDebPackages(configs, registry, suite, base.DebPackages)
				groups := groupDebPackages(base.DebPackages, blocked)
				replacements := d.findDebReplacements(ctx, configs, registry, archive, suite, base.DebPackages, groups)
				raw, compressed, err := writeDebPackages(d.applyDebReplacements(ctx, archive, suite, component, arch, base.DebPackages, groups, replacements))
				if err != nil {
					return err
				}
				mu.Lock()
				defer mu.Unlock()
				release = base.DebRelease
				files[component+"/binary-"+arch+"/Packages"] = raw
				files[component+"/binary-"+arch+"/Packages.xz"] = compressed
				return nil
			})
		}
	}
	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("failed to build debian index: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s/%s has no supported component or architecture", archive, suite)
	}

	privateKey, _, err := d.dependencyProxyService.GetOrCreateDebSigningKey(ctx, configs.Secret)
	if err != nil {
		return nil, err
	}
	releaseText, inRelease, releaseGPG, err := signDebRelease(privateKey, updateDebRelease(release, files))
	if err != nil {
		return nil, err
	}

	size := len(inRelease) + len(releaseText) + len(releaseGPG)
	for _, data := range slices.Collect(maps.Values(files)) {
		size += len(data)
		hash := sha256.Sum256(data)
		files["by-hash/"+hex.EncodeToString(hash[:])] = data
	}
	files["InRelease"] = inRelease
	files["Release"] = releaseText
	files["Release.gpg"] = releaseGPG

	slog.Info("Built debian index", "archive", archive, "suite", suite, "took", time.Since(start))
	return &debIndex{files: files, size: size}, nil
}

func (idx *debIndex) lookup(rest string) ([]byte, bool) {
	if _, hash, ok := strings.Cut(rest, "/by-hash/SHA256/"); ok {
		rest = "by-hash/" + hash
	}
	data, ok := idx.files[rest]
	return data, ok
}

func debUpstream(registry, requestPath string) (string, string) {
	archive, rest, ok := strings.Cut(requestPath, "/snapshot/")
	if !ok {
		return registry, requestPath
	}
	return shared.DebSnapshotRegistry, archive + "/" + rest
}
