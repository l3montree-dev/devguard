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

package normalize

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
)

// celParseEnv only parses, so the expressions are not type checked.
var celParseEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(cel.EnableMacroCallTracking())
})

type NormalizedCELExpression struct {
	CELExpression string
	CVEScope      *string
}

func NormalizeCELExpression(celExpression string) (NormalizedCELExpression, error) {
	env, err := celParseEnv()
	if err != nil {
		return NormalizedCELExpression{}, fmt.Errorf("could not create CEL environment: %w", err)
	}
	parsed, issues := env.Parse(celExpression)
	if issues != nil && issues.Err() != nil {
		return NormalizedCELExpression{}, fmt.Errorf("invalid CEL expression: %w", issues.Err())
	}

	nativeAST := parsed.NativeRep()
	sourceInfo := nativeAST.SourceInfo()
	root := nativeAST.Expr()

	// macros like exists are printed from their macro call, so those have to be normalized as well
	roots := []celast.Expr{root}
	for _, macroCall := range sourceInfo.MacroCalls() {
		roots = append(roots, macroCall)
	}

	normalizer := &commutativeNormalizer{
		factory:    celast.NewExprFactory(),
		sourceInfo: sourceInfo,
		nextID:     maxExprID(roots) + 1,
	}
	for _, r := range roots {
		if err := normalizer.normalize(r); err != nil {
			return NormalizedCELExpression{}, err
		}
	}

	normalized, err := cel.AstToString(parsed)
	if err != nil {
		return NormalizedCELExpression{}, fmt.Errorf("could not print CEL expression: %w", err)
	}

	return NormalizedCELExpression{CELExpression: normalized, CVEScope: cveScope(root)}, nil
}

func CVEScopeOfCELExpression(celExpression string) *string {
	if !strings.Contains(celExpression, "vuln.cveId") {
		return nil
	}
	env, err := celParseEnv()
	if err != nil {
		return nil
	}
	parsed, issues := env.Parse(celExpression)
	if issues != nil && issues.Err() != nil {
		return nil
	}
	return cveScope(parsed.NativeRep().Expr())
}

func cveScope(root celast.Expr) *string {
	for _, operand := range flattenCalls(root, operators.LogicalAnd) {
		if cveID, ok := cveCheck(operand); ok {
			return &cveID
		}
	}
	return nil
}

func cveCheck(e celast.Expr) (string, bool) {
	if e.Kind() != celast.CallKind || e.AsCall().FunctionName() != operators.Equals || len(e.AsCall().Args()) != 2 {
		return "", false
	}
	field, value := e.AsCall().Args()[0], e.AsCall().Args()[1]
	if field.Kind() != celast.SelectKind || field.AsSelect().IsTestOnly() || field.AsSelect().FieldName() != "cveId" {
		return "", false
	}
	operand := field.AsSelect().Operand()
	if operand.Kind() != celast.IdentKind || operand.AsIdent() != "vuln" || value.Kind() != celast.LiteralKind {
		return "", false
	}
	cveID, ok := value.AsLiteral().(types.String)
	if !ok || cveID == "" {
		return "", false
	}
	return string(cveID), true
}

type commutativeNormalizer struct {
	factory    celast.ExprFactory
	sourceInfo *celast.SourceInfo
	nextID     int64
}

func (normalizer *commutativeNormalizer) normalize(root celast.Expr) error {
	var err error
	celast.PostOrderVisit(root, celast.NewExprVisitor(func(e celast.Expr) {
		if err != nil || e.Kind() != celast.CallKind {
			return
		}
		function := e.AsCall().FunctionName()
		if function != operators.LogicalAnd && function != operators.LogicalOr {
			return
		}

		err = normalizer.sortOperands(e, function)
	}))
	return err
}

func (normalizer *commutativeNormalizer) sortOperands(e celast.Expr, function string) error {
	type operand struct {
		expr celast.Expr
		key  string
	}
	flattened := flattenCalls(e, function)
	operands := make([]operand, len(flattened))
	for i, expr := range flattened {
		key, err := cel.ExprToString(expr, normalizer.sourceInfo)
		if err != nil {
			return fmt.Errorf("could not print CEL expression: %w", err)
		}
		operands[i] = operand{expr: expr, key: key}
	}
	sort.SliceStable(operands, func(i, j int) bool {
		return operands[i].key < operands[j].key
	})

	chain := operands[0].expr
	for _, op := range operands[1:] {
		chain = normalizer.factory.NewCall(normalizer.nextID, function, chain, op.expr)
		normalizer.nextID++
	}
	e.SetKindCase(chain)
	return nil
}

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

func maxExprID(roots []celast.Expr) int64 {
	var maxID int64
	for _, root := range roots {
		celast.PreOrderVisit(root, celast.NewExprVisitor(func(e celast.Expr) {
			maxID = max(maxID, e.ID())
		}))
	}
	return maxID
}
