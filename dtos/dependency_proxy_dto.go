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
	"fmt"

	"gopkg.in/yaml.v3"
)

type URLRegistryConfig struct {
	URL string `validate:"required,url"`
}

func (c URLRegistryConfig) GetURL() string { return c.URL }

// DebianRegistryConfig is a custom debian registry. Its Release must be signed by Keyring,
// because the proxy re-signs the index with its own key.
type DebianRegistryConfig struct {
	URLRegistryConfig `yaml:",inline"`
	Keyring           *string `yaml:"keyring" validate:"pgp_keyring"`
}

type RegistryConfig interface {
	GetURL() string
}

type RegistryConfigs map[string]RegistryConfig

func (r RegistryConfigs) DebConfig() *DebianRegistryConfig {
	if config, ok := r["deb"]; ok {
		if debConfig, ok := config.(DebianRegistryConfig); ok {
			return &debConfig
		}
	}
	return nil
}

func (r *RegistryConfigs) UnmarshalYAML(node *yaml.Node) error {
	var raw map[string]yaml.Node
	if err := node.Decode(&raw); err != nil {
		return err
	}

	*r = make(RegistryConfigs, len(raw))
	for eco, value := range raw {
		switch eco {
		case "deb":
			var config DebianRegistryConfig
			if err := value.Decode(&config); err != nil {
				return fmt.Errorf("registries.%s: %w", eco, err)
			}
			(*r)[eco] = config
		case "npm", "go", "pypi", "maven", "composer":
			var url string
			if err := value.Decode(&url); err != nil {
				return fmt.Errorf("registries.%s: %w", eco, err)
			}
			(*r)[eco] = URLRegistryConfig{URL: url}
		default:
			return fmt.Errorf("registries.%s: unsupported ecosystem", eco)
		}
	}
	return nil
}

// DependencyProxyConfig is the config-file payload persisted for the dependency proxy.
type DependencyProxyConfig struct {
	Registries RegistryConfigs `yaml:"registries" validate:"dive,keys,oneof=npm go pypi maven composer deb,endkeys,required"`
}

// dependencyProxyConfigFileID is the key under which dependency-proxy settings
// are stored in an org/project/asset ConfigFiles map.
const DependencyProxyConfigFileID = "dependency-proxy-configs"

func ValidateDependencyProxyConfigFile(content []byte) error {
	var cfg DependencyProxyConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return err
	}
	return V.Struct(cfg)
}
