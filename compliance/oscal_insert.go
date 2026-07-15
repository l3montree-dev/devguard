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

package compliance

import (
	"regexp"
	"strings"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// insertPattern matches OSCAL markup insert spans, e.g. "{{ insert: param, arch.2.2-prm1 }}".
// The first group is the insert type (param, title, prop, link, ...), the second is the id-ref
var insertPattern = regexp.MustCompile(`\{\{\s*insert:\s*([a-zA-Z][a-zA-Z0-9_-]*)\s*,\s*([^}]+?)\s*\}\}`)

type InsertResolverFunc func(idRef string, ctx *ResolveContext) (string, bool)

type ResolveContext struct {
	Params   map[string]oscalTypes.Parameter
	Controls map[string]oscalTypes.Control
	Groups   map[string]oscalTypes.Group
}

func NewResolveContext(catalog *oscalTypes.Catalog) *ResolveContext {
	ctx := &ResolveContext{
		Params:   map[string]oscalTypes.Parameter{},
		Controls: map[string]oscalTypes.Control{},
		Groups:   map[string]oscalTypes.Group{},
	}
	if catalog == nil {
		return ctx
	}

	indexParams(ctx, catalog.Params)
	for _, g := range derefGroups(catalog.Groups) {
		indexGroup(ctx, g)
	}
	for _, c := range derefControls(catalog.Controls) {
		indexControl(ctx, c)
	}
	return ctx
}

func indexGroup(ctx *ResolveContext, g oscalTypes.Group) {
	if g.ID != "" {
		ctx.Groups[g.ID] = g
	}
	indexParams(ctx, g.Params)
	for _, c := range derefControls(g.Controls) {
		indexControl(ctx, c)
	}
	for _, sub := range derefGroups(g.Groups) {
		indexGroup(ctx, sub)
	}
}

func indexControl(ctx *ResolveContext, c oscalTypes.Control) {
	if c.ID != "" {
		ctx.Controls[c.ID] = c
	}
	indexParams(ctx, c.Params)
	for _, sub := range derefControls(c.Controls) {
		indexControl(ctx, sub)
	}
}

func indexParams(ctx *ResolveContext, params *[]oscalTypes.Parameter) {
	if params == nil {
		return
	}
	for _, p := range *params {
		ctx.Params[p.ID] = p
	}
}

var insertResolvers = map[string]InsertResolverFunc{
	"param": resolveParamInsert,
}

func RegisterInsertResolver(insertType string, resolver InsertResolverFunc) {
	insertResolvers[insertType] = resolver
}

func resolveParamInsert(idRef string, ctx *ResolveContext) (string, bool) {
	param, ok := ctx.Params[idRef]
	if !ok {
		return "", false
	}

	switch {
	case param.Values != nil && len(*param.Values) > 0:
		return strings.Join(*param.Values, ", "), true
	case param.Select != nil && param.Select.Choice != nil && len(*param.Select.Choice) > 0:
		return strings.Join(*param.Select.Choice, ", "), true
	case param.Label != "":
		return param.Label, true
	default:
		return "", false
	}
}

func ResolveInserts(prose string, ctx *ResolveContext) string {
	if ctx == nil || !strings.Contains(prose, "insert:") {
		return prose
	}

	return insertPattern.ReplaceAllStringFunc(prose, func(match string) string {
		groups := insertPattern.FindStringSubmatch(match)
		if len(groups) != 3 {
			return match
		}
		insertType := groups[1]
		idRef := groups[2]

		resolver, ok := insertResolvers[insertType]
		if !ok {
			return match
		}

		resolved, ok := resolver(idRef, ctx)
		if !ok {
			return match
		}
		return resolved
	})
}
