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
	"github.com/l3montree-dev/devguard/utils"
)

type programKey struct {
	env        *cel.Env
	expression string
}

var programCache = utils.NewTTLCache[programKey, cel.Program](time.Hour, 10_000, nil)

var baseEnv = sync.OnceValues(func() (*cel.Env, error) {
	semverOpts, err := semverLib()
	if err != nil {
		return nil, err
	}
	return cel.NewEnv(utils.Merge(semverOpts, purlLib(),
		[]cel.EnvOption{cel.OptionalTypes(),
			cel.Function("now",
				cel.Overload("now_timestamp", []*cel.Type{}, cel.TimestampType,
					cel.FunctionBinding(func(args ...ref.Val) ref.Val {
						return types.Timestamp{Time: time.Now()}
					}),
				),
			),
		},
	)...)
})

func compile(env *cel.Env, expression string) (cel.Program, error) {
	key := programKey{env: env, expression: expression}
	cachedPrg, cacheHit := programCache.Get(key)
	if cacheHit {
		return cachedPrg, nil
	}
	ast, iss := env.Compile(expression)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	if ast.OutputType() != cel.BoolType && ast.OutputType() != cel.DynType {
		return nil, fmt.Errorf("failed to compile CEL expression. Type is not a bool: %s", ast.OutputType())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to build CEL program: %w", err)
	}
	programCache.Set(key, prg)
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
