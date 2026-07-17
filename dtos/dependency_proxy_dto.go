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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package dtos

import (
	"encoding/json"
)

// DependencyProxyConfig is the config-file payload persisted for the dependency proxy.
type DependencyProxyConfig struct {
	Rules         string `json:"rules"`
	MinReleaseAge int    `json:"minReleaseAge" validate:"gte=0,lte=87600"` // in hours, capped at 10 years
}

// dependencyProxyConfigFileID is the key under which dependency-proxy settings
// are stored in an org/project/asset ConfigFiles map.
const DependencyProxyConfigFileID = "dependency-proxy-configs"

// validateConfigFile validates a config-file payload before it is persisted.
// Only config files with known schemas are checked; unknown ones pass through.
func ValidateConfigFile(content []byte) error {
	var cfg DependencyProxyConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return err
	}
	if err := V.Struct(cfg); err != nil {
		return err
	}
	return nil
}
