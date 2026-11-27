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

package celrules

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
)

type Refs struct {
	celMaps []any
	index   map[uuid.UUID]int
}

func NewRefs(assetVersions []models.AssetVersion) Refs {
	refs := Refs{celMaps: make([]any, len(assetVersions)), index: make(map[uuid.UUID]int, len(assetVersions))}
	versions := make([]*semver.Version, len(assetVersions))
	latest := map[string]int{}
	keep := func(key string, i int, greater func(j int) bool) {
		if j, ok := latest[key]; !ok || greater(j) {
			latest[key] = i
		}
	}

	for i, assetVersion := range assetVersions {
		refs.index[assetVersion.ID] = i
		celMap := assetVersion.ToCELMap()
		for _, field := range latestFields {
			celMap[field] = false
		}
		refs.celMaps[i] = celMap

		if assetVersion.Type != models.AssetVersionTag {
			continue
		}
		keep("isLatestByCreatedAt", i, func(j int) bool { return assetVersion.CreatedAt.After(assetVersions[j].CreatedAt) })

		version, err := semver.NewVersion(assetVersion.Name)
		if err != nil {
			continue
		}
		versions[i] = version
		greater := func(j int) bool { return version.GreaterThan(versions[j]) }
		keep("isLatestBySemverIncludingPrereleases", i, greater)
		if version.Prerelease() != "" {
			continue
		}
		keep("isLatestBySemverStable", i, greater)
		keep(fmt.Sprintf("isLatestBySemverInMajor/%d", version.Major()), i, greater)
		keep(fmt.Sprintf("isLatestBySemverInMinor/%d.%d", version.Major(), version.Minor()), i, greater)
	}

	for key, i := range latest {
		field, _, _ := strings.Cut(key, "/")
		refs.celMaps[i].(map[string]any)[field] = true
	}
	return refs
}

var latestFields = []string{
	"isLatestBySemverIncludingPrereleases",
	"isLatestBySemverStable",
	"isLatestBySemverInMajor",
	"isLatestBySemverInMinor",
	"isLatestByCreatedAt",
}

func (r Refs) activationAt(i int) map[string]any {
	others := make([]any, 0, len(r.celMaps)-1)
	others = append(others, r.celMaps[:i]...)
	others = append(others, r.celMaps[i+1:]...)
	return map[string]any{"ref": r.celMaps[i], "otherRefs": others}
}

func (r Refs) Activation(assetVersionID uuid.UUID) (map[string]any, error) {
	i, ok := r.index[assetVersionID]
	if !ok {
		return nil, fmt.Errorf("asset version %s is not part of the refs", assetVersionID)
	}
	return r.activationAt(i), nil
}

func withRefs(env *cel.Env, err error) (*cel.Env, error) {
	if err != nil {
		return nil, err
	}
	return env.Extend(
		cel.Variable("ref", cel.AnyType),
		cel.Variable("otherRefs", cel.ListType(cel.AnyType)),
	)
}
