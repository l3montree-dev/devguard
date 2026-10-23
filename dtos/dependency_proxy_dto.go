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

// DependencyProxyConfig is the config-file payload persisted for the dependency proxy.
type DependencyProxyConfig struct {
	Registries map[string]string `yaml:"registries" validate:"omitempty,dive,keys,oneof=npm go pypi maven composer deb,endkeys,required,url"`
}

// dependencyProxyConfigFileID is the key under which dependency-proxy settings
// are stored in an org/project/asset ConfigFiles map.
const DependencyProxyConfigFileID = "dependency-proxy-configs"
