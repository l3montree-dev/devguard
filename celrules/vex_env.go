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
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// VEXCelEnv is the CEL environment used for real VEX rule matching, where the
// vuln's real artifacts are known.
var VEXCelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return newVEXCelEnv(func(pattern, path, artifactPurls []string) bool {
		return PathPattern(pattern).Matches(path, artifactPurls)
	})
})

// SoftMatchCelEnv is for callers that haven't loaded artifacts at all - e.g.
// crowdsourced-vexing's soft-match phase, run against representative vulns
// before their real artifacts are known. See PathPattern.SoftMatches for the
// semantics this widens matchesPattern to.
var SoftMatchCelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return newVEXCelEnv(func(pattern, path, _ []string) bool {
		return PathPattern(pattern).SoftMatches(path)
	})
})

func newVEXCelEnv(matchesPattern func(pattern, path, artifactPurls []string) bool) (*cel.Env, error) {
	base, err := baseEnv()
	if err != nil {
		return nil, err
	}
	return base.Extend(
		cel.Variable("vuln", cel.AnyType),
		cel.Function("matchesPattern",
			cel.Overload(
				"matchesPattern_vuln_list",
				[]*cel.Type{cel.DynType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					path, err := stringListField(lhs, "vulnerabilityPath")
					if err != nil {
						return types.NewErr("matchesPattern: invalid vuln.vulnerabilityPath: %v", err)
					}
					artifactPurls, err := stringListField(lhs, "artifactPurls")
					if err != nil {
						return types.NewErr("matchesPattern: invalid vuln.artifactPurls: %v", err)
					}
					pattern, err := toStringList(rhs)
					if err != nil {
						return types.NewErr("matchesPattern: invalid pattern argument: %v", err)
					}
					return types.Bool(matchesPattern(pattern, path, artifactPurls))
				}),
			),
		),
	)
}

func toStringList(val ref.Val) ([]string, error) {
	native, err := val.ConvertToNative(reflect.TypeFor[[]string]())
	if err != nil {
		return nil, err
	}
	return native.([]string), nil
}

func stringListField(mapVal ref.Val, key string) ([]string, error) {
	mapper, ok := mapVal.(traits.Mapper)
	if !ok {
		return nil, fmt.Errorf("expected a map, got %s", mapVal.Type().TypeName())
	}
	fieldVal, found := mapper.Find(types.String(key))
	if !found || fieldVal == nil {
		return nil, nil
	}
	if types.IsError(fieldVal) {
		return nil, fmt.Errorf("field %q: %v", key, fieldVal)
	}
	return toStringList(fieldVal)
}
