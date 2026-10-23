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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/package-url/packageurl-go"
)

var baseEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Function("now",
			cel.Overload("now_timestamp", []*cel.Type{}, cel.TimestampType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					return types.Timestamp{Time: time.Now()}
				}),
			),
		),
		cel.Function("matchesPurl",
			cel.Overload("matchesPurl_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					purl, ok := lhs.Value().(string)
					if !ok {
						return types.NewErr("matchesPurl: invalid purl argument: %v", lhs)
					}
					pattern, ok := rhs.Value().(string)
					if !ok {
						return types.NewErr("matchesPurl: invalid pattern argument: %v", rhs)
					}
					purlObj, err := packageurl.FromString(purl)
					if err != nil {
						return types.NewErr("matchesPurl: invalid purl: %v", err)
					}
					patternObj, err := packageurl.FromString(pattern)
					if err != nil {
						return types.NewErr("matchesPurl: invalid pattern purl: %v", err)
					}

					matches, err := PurlVersionMatches(patternObj, purlObj)
					if err != nil {
						return types.NewErr("matchesPurl: %v", err)
					}

					return types.Bool(matches)
				}),
			),
		),
	)
})

func compile(env *cel.Env, expression string) (cel.Program, error) {
	ast, iss := env.Compile(expression)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to build CEL program: %w", err)
	}
	return prg, nil
}

func evalBool(prg cel.Program, activation map[string]any) (bool, error) {
	out, _, err := prg.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, errors.New("CEL expression did not evaluate to a bool")
	}
	return result, nil
}
