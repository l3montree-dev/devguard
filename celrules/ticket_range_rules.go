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

	"github.com/google/cel-go/cel"
	"github.com/l3montree-dev/devguard/database/models"
)

func CompileTicketRangeRule(expression string) (cel.Program, error) {
	env, err := VEXCelEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	return compile(env, expression)
}

func EvalTicketRangeRule(expression string, vuln models.DependencyVuln, assetVersion models.AssetVersion) (bool, error) {
	prg, err := CompileTicketRangeRule(expression)
	if err != nil {
		return false, err
	}
	vulnMap, err := vulnToCELMap(vuln)
	if err != nil {
		return false, err
	}
	vulnMap["ref"] = assetVersion.ToCELMap()
	return evalBool(prg, map[string]any{"vuln": vulnMap})
}
