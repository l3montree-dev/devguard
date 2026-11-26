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
	"log/slog"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/l3montree-dev/devguard/database/models"
)

// DefaultAssetVersionRetentionPolicy keeps tags, the default branch and every branch which was created or received an upload within the last 7 days.
// it is the column default of assets.asset_version_retention_policy - keep both in sync.
const DefaultAssetVersionRetentionPolicy = `ref.type == "tag" || ref.defaultBranch || timestamp(ref.createdAt) > now() - duration("168h") || (has(ref.lastUploadAt) && timestamp(ref.lastUploadAt) > now() - duration("168h"))`

var assetVersionCelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return withRefs(baseEnv())
})

func CompileAssetVersionRetentionPolicy(expression string) (cel.Program, error) {
	env, err := assetVersionCelEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	return compile(env, expression)
}

// AssetVersionsToDelete returns the asset versions of a single asset which the retention policy does not keep.
// every asset version the policy fails to evaluate for is kept - a broken policy must never delete data.
func AssetVersionsToDelete(policy string, assetVersions []models.AssetVersion) ([]models.AssetVersion, error) {
	prg, err := CompileAssetVersionRetentionPolicy(policy)
	if err != nil {
		return nil, err
	}

	refs := NewRefs(assetVersions)
	var toDelete []models.AssetVersion
	for i, assetVersion := range assetVersions {
		keep, err := evalBool(prg, refs.activationAt(i))
		if err != nil {
			slog.Warn("could not evaluate asset version retention policy, keeping asset version", "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
			continue
		}
		if !keep {
			toDelete = append(toDelete, assetVersion)
		}
	}
	return toDelete, nil
}
