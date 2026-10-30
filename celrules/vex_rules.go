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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
)

// CompiledVEXRule pairs a compiled CEL program with the CVE scope of the rule it
// came from, so EvalCompiledVEXRules can narrow evaluation to just the vulns
// sharing that CVE instead of cross-evaluating every rule against every vuln
// in the batch (a scoped rule's own vuln.cveId == "..." check would reject
// every mismatch anyway - this just skips paying for that Eval call at all).
type CompiledVEXRule struct {
	Program  cel.Program
	CVEScope *string
}

// CompileVEXRules compiles every rule's CEL expression against the real-match
// CelEnv. cel.Env is safe for concurrent Compile/Program calls, so rules are
// compiled in parallel batches.
func CompileVEXRules(ctx context.Context, rules []models.UpstreamVEXRule) (map[string]CompiledVEXRule, error) {
	return compileVEXRulesWithEnv(ctx, rules, VEXCelEnv)
}

// CompileVEXRulesForSoftMatching is CompileVEXRules against SoftMatchCelEnv, for
// crowdsourced-vexing's soft-match phase over vulns without real artifacts.
func CompileVEXRulesForSoftMatching(ctx context.Context, rules []models.UpstreamVEXRule) (map[string]CompiledVEXRule, error) {
	return compileVEXRulesWithEnv(ctx, rules, SoftMatchCelEnv)
}

func compileVEXRulesWithEnv(ctx context.Context, rules []models.UpstreamVEXRule, env func() (*cel.Env, error)) (map[string]CompiledVEXRule, error) {
	celEnv, err := env()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	partials, err := utils.ParallelBatches(rules, func(batch []models.UpstreamVEXRule) (map[string]CompiledVEXRule, error) {
		local := make(map[string]CompiledVEXRule, len(batch))
		for _, rule := range batch {
			if rule.CELExpression == "" {
				continue
			}
			prg, err := compile(celEnv, rule.CELExpression)
			if err != nil {
				return nil, err
			}

			local[rule.ID] = CompiledVEXRule{Program: prg, CVEScope: rule.CVEScope}
		}
		return local, nil
	})
	if err != nil {
		return nil, err
	}

	compiled := make(map[string]CompiledVEXRule, len(rules))
	for _, local := range partials {
		for id, cr := range local {
			compiled[id] = cr
		}
	}
	return compiled, nil
}

// returns map keyed by vulnID and value is a list of ruleIDs that match that vuln
func EvalCompiledVEXRules(ctx context.Context, compiled map[string]CompiledVEXRule, vulnMaps []map[string]any) (map[string][]string, error) {
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
	for ruleID, cr := range compiled {
		relVuln := vulnMaps
		if cr.CVEScope != nil {
			relVuln = cveToVulnMap[*cr.CVEScope]
		}
		jobs = append(jobs, ruleJob{id: ruleID, prg: cr.Program, relVuln: relVuln})
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
				result, err := evalBool(job.prg, activation)
				if err != nil {
					return nil, fmt.Errorf("rule %s: %w", job.id, err)
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

func vulnToCELMap(vuln models.DependencyVuln) (map[string]any, error) {
	vulnMap := vuln.ToCELMap()
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
		prepared[vuln.ID.String()] = vulnMap
	}
	return prepared, nil
}

func IdentityOfRule(rule models.UpstreamVEXRule) (string, error) {
	// the identity of a vex rule is inside the cel expression AND the assessment.
	identity := string(rule.EventType) + "||" + string(rule.MechanicalJustification) + "||"

	// now we need to parse the CEL expression. Since it might contain && and || which semantically do not differ based on the order of the expressions, we need to sort the expressions inside the CEL expression to get a consistent identity for the same rule.
	// we can do so by parsing the expression into the AST
	celEnv, err := VEXCelEnv()
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
