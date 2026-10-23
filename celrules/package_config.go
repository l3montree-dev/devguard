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

	"gopkg.in/yaml.v3"
)

func ParsePackageRules(content string) ([]CompiledPackageRule, error) {
	var cfg struct {
		Rules []PackageRule `yaml:"rules"`
	}

	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	compiledRules, err := CompilePackageRules(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("failed to compile rules: %w", err)
	}

	return compiledRules, nil
}
