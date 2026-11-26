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
	latest := -1
	var latestVersion *semver.Version
	for i, assetVersion := range assetVersions {
		refs.index[assetVersion.ID] = i
		if assetVersion.Type != models.AssetVersionTag {
			continue
		}
		version, err := semver.NewVersion(assetVersion.Name)
		if err != nil || version.Prerelease() != "" {
			continue
		}
		if latestVersion == nil || version.GreaterThan(latestVersion) {
			latest, latestVersion = i, version
		}
	}

	var latestRef map[string]any
	if latest >= 0 {
		latestRef = assetVersions[latest].ToCELMap()
		latestRef["isLatest"] = true
	}
	for i, assetVersion := range assetVersions {
		celMap := assetVersion.ToCELMap()
		celMap["isLatest"] = i == latest
		if latestRef != nil {
			celMap["latestRef"] = latestRef
		}
		refs.celMaps[i] = celMap
	}
	return refs
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
