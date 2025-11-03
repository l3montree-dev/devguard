// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package scanner

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func MaybeLoginIntoOciRegistry(ctx context.Context) error {
	if config.RuntimeBaseConfig.Username != "" && config.RuntimeBaseConfig.Password != "" && config.RuntimeBaseConfig.Registry != "" {
		// login to the registry
		err := Login(ctx, config.RuntimeBaseConfig.Username, config.RuntimeBaseConfig.Password, config.RuntimeBaseConfig.Registry)
		if err != nil {
			slog.Error("login failed", "err", err)
			return err
		}

		slog.Debug("logged in", "registry", config.RuntimeBaseConfig.Registry)
	} else {
		slog.Debug("skipping oci login - no registry / credentials provided")
	}
	return nil
}

func BomFromBytes(bomStr []byte) (*cdx.BOM, error) {
	// Extract string encoded json as BOM
	var bom cdx.BOM
	err := json.Unmarshal(bomStr, &bom)
	if err != nil {
		return nil, err
	}
	return &bom, nil
}
