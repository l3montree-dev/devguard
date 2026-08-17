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
	"regexp"
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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/package-url/packageurl-go"
)

// CelEnv is the CEL environment used for real VEX rule matching, where the
// vuln's real artifacts are known.
var CelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return newCelEnv(func(pattern, path, artifactPurls []string) bool {
		return PathPattern(pattern).Matches(path, artifactPurls)
	})
})

// SoftMatchCelEnv is for callers that haven't loaded artifacts at all - e.g.
// crowdsourced-vexing's soft-match phase, run against representative vulns
// before their real artifacts are known. See PathPattern.SoftMatches for the
// semantics this widens matchesPattern to.
var SoftMatchCelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return newCelEnv(func(pattern, path, _ []string) bool {
		return PathPattern(pattern).SoftMatches(path)
	})
})

func newCelEnv(matchesPattern func(pattern, path, artifactPurls []string) bool) (*cel.Env, error) {
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
					return types.Bool(matchesPattern(pattern, path, artifactPurls))
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
}

/*
Thats a typical example of a rule that exists in a cveId scope.
vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*", "pkg:golang/k8s.io/component-helpers@v1.35.7-k3s1", "*", "pkg:golang/stdlib@v1.25.0"])
We just need to extract the CVE-2025-61725 part and store it in the CompiledRule.CVEScope field.
*/
var scopeRegex = regexp.MustCompile(`^vuln\.cveId\s*==\s*"([^"]+)" &&`)

func ExtractCVEScopeFromCELExpression(expr string) *string {
	if !strings.Contains(expr, "vuln.cveId") {
		return nil
	}
	matches := scopeRegex.FindStringSubmatch(expr)
	if len(matches) < 2 {
		return nil
	}
	cveID := matches[1]
	return &cveID
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

func PrepareVulnsForEval(ctx context.Context, vulns []models.DependencyVuln) ([]map[string]any, error) {
	prepared := make([]map[string]any, len(vulns))
	for i, vuln := range vulns {
		vulnMap, err := vulnToCELMap(vuln)
		if err != nil {
			return nil, err
		}
		prepared[i] = vulnMap
	}
	return prepared, nil
}

func PrepareVulnsForEvalMap(ctx context.Context, vulns []models.DependencyVuln) (map[string]map[string]any, error) {
	prepared := make(map[string]map[string]any, len(vulns))
	for _, vuln := range vulns {
		vulnMap, err := vulnToCELMap(vuln)
		if err != nil {
			return nil, err
		}
		prepared[vuln.Vulnerability.ID.String()] = vulnMap
	}
	return prepared, nil
}

// CompileRules compiles every rule's CEL expression against the real-match
// CelEnv. cel.Env is safe for concurrent Compile/Program calls, so rules are
// compiled in parallel batches.
func CompileRules(ctx context.Context, rules []models.UpstreamVEXRule) (map[string]cel.Program, error) {
	return compileRulesWithEnv(ctx, rules, CelEnv)
}

// CompileRulesForSoftMatching is CompileRules against SoftMatchCelEnv, for
// crowdsourced-vexing's soft-match phase over vulns without real artifacts.
func CompileRulesForSoftMatching(ctx context.Context, rules []models.UpstreamVEXRule) (map[string]cel.Program, error) {
	return compileRulesWithEnv(ctx, rules, SoftMatchCelEnv)
}

func compileRulesWithEnv(ctx context.Context, rules []models.UpstreamVEXRule, env func() (*cel.Env, error)) (map[string]cel.Program, error) {
	celEnv, err := env()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	partials, err := utils.ParallelBatches(rules, func(batch []models.UpstreamVEXRule) (map[string]cel.Program, error) {
		local := make(map[string]cel.Program, len(batch))
		for _, rule := range batch {
			if rule.CELExpression == "" {
				continue
			}
			ast, iss := celEnv.Compile(rule.CELExpression)
			if iss != nil && iss.Err() != nil {
				return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
			}
			prg, err := celEnv.Program(ast)
			if err != nil {
				return nil, fmt.Errorf("failed to build CEL program: %w", err)
			}

			local[rule.ID] = prg
		}
		return local, nil
	})
	if err != nil {
		return nil, err
	}

	compiled := make(map[string]cel.Program, len(rules))
	for _, local := range partials {
		for id, cr := range local {
			compiled[id] = cr
		}
	}
	return compiled, nil
}

// returns map keyed by vulnID and value is a list of ruleIDs that match that vuln
func EvalCompiledRules(ctx context.Context, compiled map[string]cel.Program, vulnMaps []map[string]any) (map[string][]string, error) {
	cveToVulnMap := make(map[string][]map[string]any, len(vulnMaps))
	for _, vulnMap := range vulnMaps {
		vulnCVEID, _ := vulnMap["cveId"].(string)
		if vulnCVEID == "" {
			continue
		}
		cveToVulnMap[vulnCVEID] = append(cveToVulnMap[vulnCVEID], vulnMap)
	}

	type ruleJob struct {
		id      string
		prg     cel.Program
		relVuln []map[string]any
	}

	jobs := make([]ruleJob, 0, len(compiled))
	for ruleID, prg := range compiled {
		jobs = append(jobs, ruleJob{id: ruleID, prg: prg, relVuln: vulnMaps})
	}

	partials, err := utils.ParallelBatches(jobs, func(batch []ruleJob) (map[string][]string, error) {
		local := make(map[string][]string)
		// each batch runs on a single goroutine, so this activation map can be
		// reused across every Eval call in the batch instead of allocating a
		// fresh one-entry map per evaluation - CEL only reads it during the
		// call, it doesn't retain it afterward.
		activation := map[string]any{"vuln": nil}
		for _, job := range batch {
			for _, vulnMap := range job.relVuln {
				vulnID := vulnMap["id"].(string)
				activation["vuln"] = vulnMap
				out, _, err := job.prg.Eval(activation)
				if err != nil {
					return nil, fmt.Errorf("failed to evaluate CEL expression for rule %s: %w", job.id, err)
				}

				result, ok := out.Value().(bool)
				if !ok {
					return nil, fmt.Errorf("CEL expression for rule %s did not evaluate to a bool, got %T", job.id, out.Value())
				}
				if result {
					local[vulnID] = append(local[vulnID], job.id)
				}
			}
		}
		return local, nil
	})
	if err != nil {
		return nil, err
	}

	results := make(map[string][]string, len(compiled))
	for _, local := range partials {
		for vulnID, ruleIDs := range local {
			results[vulnID] = append(results[vulnID], ruleIDs...)
		}
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

func IdentityOfRule(rule models.UpstreamVEXRule) (string, error) {
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
