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
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

type PackageRule struct {
	Name   string `yaml:"name"`
	Action Action `yaml:"action"`
	Expr   string `yaml:"expr"`
}

type CompiledPackageRule struct {
	Rule    PackageRule
	Program cel.Program
}

func CompilePackageRules(rules []PackageRule) ([]CompiledPackageRule, error) {
	var compiledRules []CompiledPackageRule

	for _, rule := range rules {
		if rule.Action != ActionAllow && rule.Action != ActionDeny {
			return nil, fmt.Errorf("failed to validate action for rule %s", rule.Name)
		}

		prg, err := compilePackageExpr(rule.Expr)
		if err != nil {
			return nil, fmt.Errorf("failed to validate expression for rule %s: %w", rule.Name, err)
		}

		compiledRules = append(compiledRules, CompiledPackageRule{Rule: rule, Program: prg})
	}

	return compiledRules, nil
}

func EvaluatePackage(rules []CompiledPackageRule, p Package) (bool, string, error) {
	blocked := false
	ruleName := ""

	for _, rule := range rules {
		evaluation, err := evalPackage(rule.Program, p)
		if err != nil {
			return true, rule.Rule.Name, fmt.Errorf("failed to evaluate for rule %s: %w", rule.Rule.Name, err)
		}

		if evaluation {
			blocked = rule.Rule.Action == ActionDeny
			ruleName = rule.Rule.Name
		}
	}
	return blocked, ruleName, nil
}
