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

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/pkg/errors"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func dockerLogin(ctx context.Context) error {
	if config.RuntimeBaseConfig.Username != "" && config.RuntimeBaseConfig.Password != "" && config.RuntimeBaseConfig.Registry != "" {
		// login to the registry
		err := login(ctx, config.RuntimeBaseConfig.Username, config.RuntimeBaseConfig.Password, config.RuntimeBaseConfig.Registry)
		if err != nil {
			slog.Error("login failed", "err", err)
			return err
		}

		slog.Info("logged in", "registry", config.RuntimeBaseConfig.Registry)
	} else {
		slog.Info("skipping docker login - no registry / credentials provided")
	}
	return nil
}

func bomToString(bom *cdx.BOM) ([]byte, error) {
	bomBuffer := &bytes.Buffer{}
	encoder := cdx.NewBOMEncoder(bomBuffer, cdx.BOMFileFormatJSON)
	if err := encoder.Encode(bom); err != nil {
		return nil, err
	}
	return bomBuffer.Bytes(), nil
}

func bomToFile(bom *cdx.BOM, file *os.File) error {
	data, err := bomToString(bom)
	if err != nil {
		return err
	}

	err = os.WriteFile(file.Name(), data, 0600)
	return err
}

func bomFromString(bomStr []byte) (*cdx.BOM, error) {
	// Extract string encoded json as BOM
	var bom cdx.BOM
	err := json.Unmarshal(bomStr, &bom)
	if err != nil {
		return nil, err
	}
	return &bom, nil
}

func bomFromFile(file *os.File) (*cdx.BOM, error) {
	bomStr, err := os.ReadFile(file.Name())
	if err != nil {
		return nil, errors.Wrap(err, "failed to read bom file")
	}

	bom, err := bomFromString(bomStr)
	return bom, err
}
