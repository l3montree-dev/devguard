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

package vexrules

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/parser"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/l3montree-dev/devguard/database/models"

	"github.com/package-url/packageurl-go"
)

var CelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(
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
					matches := PathPattern(pattern).Matches(path, artifactPurls)
					return types.Bool(matches)
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

const programCacheSize = 2048

var programCache = must(lru.New[string, cel.Program](programCacheSize))

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func getOrCompileProgram(celEnv *cel.Env, expr string) (cel.Program, error) {
	if prg, ok := programCache.Get(expr); ok {
		return prg, nil
	}

	ast, iss := celEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}
	prg, err := celEnv.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to build CEL program: %w", err)
	}

	programCache.Add(expr, prg)
	return prg, nil
}

func vulnToCELMap(vuln models.DependencyVuln) (map[string]any, error) {
	m, err := json.Marshal(vuln)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vuln to JSON: %w", err)
	}

	var vulnMap map[string]any
	if err := json.Unmarshal(m, &vulnMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to map: %w", err)
	}
	// artifactPurls is derived (vuln.ArtifactPurls()), not a JSON field of
	// DependencyVuln, so it has to be added to the map explicitly for
	// matchesPattern(vuln, pattern) to see it.
	vulnMap["artifactPurls"] = vuln.ArtifactPurls()
	return vulnMap, nil
}

func evalCompiledRule(rule models.VEXRule, vulnMap map[string]any) (bool, error) {
	if rule.CELExpression == "" {
		return false, nil
	}

	celEnv, err := CelEnv()
	if err != nil {
		return false, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	prg, err := getOrCompileProgram(celEnv, rule.CELExpression)
	if err != nil {
		return false, err
	}

	out, _, err := prg.Eval(map[string]any{
		"vuln": vulnMap,
	})
	if err != nil {
		return false, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression did not evaluate to a bool, got %T", out.Value())
	}
	return result, nil
}

func EvalRule(ctx context.Context, rule models.VEXRule, vuln models.DependencyVuln) (bool, error) {
	if rule.CELExpression == "" {
		return false, nil
	}

	vulnMap, err := vulnToCELMap(vuln)
	if err != nil {
		return false, err
	}

	return evalCompiledRule(rule, vulnMap)
}

func EvalRules(ctx context.Context, rules []models.VEXRule, vuln models.DependencyVuln) (map[string]bool, error) {
	vulnMap, err := vulnToCELMap(vuln)
	if err != nil {
		return nil, err
	}

	results := make(map[string]bool, len(rules))
	for _, rule := range rules {
		match, err := evalCompiledRule(rule, vulnMap)
		if err != nil {
			return nil, err
		}
		results[rule.CELExpression] = match
	}
	return results, nil
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

func IdentityOfRule(rule models.VEXRule) (string, error) {
	// the identity of a vex rule is inside the cel expression AND the assessment.
	identity := string(rule.EventType) + "||" + string(rule.MechanicalJustification) + "||"

	// now we need to parse the CEL expression. Since it might contain && and || which semantically do not differ based on the order of the expressions, we need to sort the expressions inside the CEL expression to get a consistent identity for the same rule.
	// we can do so by parsing the expression into the AST
	celEnv, err := CelEnv()
	if err != nil {
		return "", fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, iss := celEnv.Compile(rule.CELExpression)
	if iss != nil && iss.Err() != nil {
		return "", fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	info := ast.NativeRep().SourceInfo()
	canonical := canonicalExprString(ast.NativeRep().Expr(), info)

	sum := sha256.Sum256([]byte(identity + canonical))
	return hex.EncodeToString(sum[:]), nil
}

// canonicalExprString renders an expression to source text via cel-go's own
// unparser, except for && and || calls: since those are commutative, their
// (recursively flattened) operands are sorted before joining, so operand
// order doesn't affect the result.
func canonicalExprString(e celast.Expr, info *celast.SourceInfo) string {
	if e.Kind() == celast.CallKind {
		if fn := e.AsCall().FunctionName(); fn == "_&&_" || fn == "_||_" {
			var operands []string
			for _, o := range flattenCalls(e, fn) {
				operands = append(operands, canonicalExprString(o, info))
			}
			sort.Strings(operands)
			return fn + "(" + strings.Join(operands, ",") + ")"
		}
	}
	s, _ := parser.Unparse(e, info)
	return s
}

// flattenCalls collects the operands of a chain of same-function calls,
// e.g. a && b && c parses as _&&_(_&&_(a,b),c); this returns [a,b,c].
func flattenCalls(e celast.Expr, fn string) []celast.Expr {
	if e.Kind() != celast.CallKind || e.AsCall().FunctionName() != fn {
		return []celast.Expr{e}
	}
	var operands []celast.Expr
	for _, a := range e.AsCall().Args() {
		operands = append(operands, flattenCalls(a, fn)...)
	}
	return operands
}
