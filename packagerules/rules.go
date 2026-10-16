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

package packagerules

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

type Rule struct {
	Name   string `yaml:"name"`
	Action Action `yaml:"action"`
	Expr   string `yaml:"expr"`
}

type CompiledRule struct {
	Rule    Rule
	Program cel.Program
}

func CompileRules(rules []Rule) ([]CompiledRule, error) {
	var compiledRules []CompiledRule

	for _, rule := range rules {
		if rule.Action != ActionAllow && rule.Action != ActionDeny {
			return nil, fmt.Errorf("failed to validate action for rule %s", rule.Name)
		}

		prg, err := Compile(rule.Expr)
		if err != nil {
			return nil, fmt.Errorf("failed to validate expression for rule %s: %w", rule.Name, err)
		}

		compiledRules = append(compiledRules, CompiledRule{Rule: rule, Program: prg})
	}

	return compiledRules, nil
}

func Evaluate(rules []CompiledRule, p Package) (bool, string, error) {
	blocked := false
	ruleName := ""

	for _, rule := range rules {
		evaluation, err := Eval(rule.Program, p)
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
