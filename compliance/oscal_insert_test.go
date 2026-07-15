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
	"testing"

	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/stretchr/testify/assert"
)

func paramWithValues(id string, values ...string) oscalTypes.Parameter {
	return oscalTypes.Parameter{ID: id, Values: &values}
}

func paramWithSelect(id string, choices ...string) oscalTypes.Parameter {
	return oscalTypes.Parameter{ID: id, Select: &oscalTypes.ParameterSelection{Choice: &choices}}
}

func paramWithLabel(id, label string) oscalTypes.Parameter {
	return oscalTypes.Parameter{ID: id, Label: label}
}

func TestResolveInserts_Param(t *testing.T) {
	t.Run("resolves from Values", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{
			"arch.2.2-prm1": paramWithValues("arch.2.2-prm1", "Gerätetyp"),
		}}
		got := ResolveInserts("Einschränken anhand von {{ insert: param, arch.2.2-prm1 }}.", ctx)
		assert.Equal(t, "Einschränken anhand von Gerätetyp.", got)
	})

	t.Run("joins multiple Values", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{
			"p1": paramWithValues("p1", "Gerätetyp", "Benutzerrolle"),
		}}
		got := ResolveInserts("{{ insert: param, p1 }}", ctx)
		assert.Equal(t, "Gerätetyp, Benutzerrolle", got)
	})

	t.Run("falls back to Select.Choice when no Values", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{
			"p1": paramWithSelect("p1", "jährlich", "quartalsweise"),
		}}
		got := ResolveInserts("{{ insert: param, p1 }}", ctx)
		assert.Equal(t, "jährlich, quartalsweise", got)
	})

	t.Run("falls back to Label when no Values or Select", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{
			"p1": paramWithLabel("p1", "Kriterien"),
		}}
		got := ResolveInserts("{{ insert: param, p1 }}", ctx)
		assert.Equal(t, "Kriterien", got)
	})

	t.Run("leaves span untouched when param is unknown", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{}}
		prose := "Text mit {{ insert: param, does-not-exist }} Platzhalter."
		got := ResolveInserts(prose, ctx)
		assert.Equal(t, prose, got)
	})

	t.Run("resolves multiple distinct inserts in the same prose", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{
			"p1": paramWithLabel("p1", "A"),
			"p2": paramWithLabel("p2", "B"),
		}}
		got := ResolveInserts("{{ insert: param, p1 }} und {{ insert: param, p2 }}", ctx)
		assert.Equal(t, "A und B", got)
	})

	t.Run("returns prose unchanged when there is no insert markup", func(t *testing.T) {
		ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{}}
		prose := "Ganz normaler Text ohne Platzhalter."
		got := ResolveInserts(prose, ctx)
		assert.Equal(t, prose, got)
	})

	t.Run("nil context returns prose unchanged", func(t *testing.T) {
		prose := "{{ insert: param, p1 }}"
		got := ResolveInserts(prose, nil)
		assert.Equal(t, prose, got)
	})
}

func TestResolveInserts_UnknownType(t *testing.T) {
	ctx := &ResolveContext{Params: map[string]oscalTypes.Parameter{}}
	prose := "Siehe {{ insert: title, some-control-id }} für Details."
	got := ResolveInserts(prose, ctx)
	assert.Equal(t, prose, got, "unregistered insert types should be left untouched")
}

func TestRegisterInsertResolver(t *testing.T) {
	RegisterInsertResolver("title", func(idRef string, ctx *ResolveContext) (string, bool) {
		c, ok := ctx.Controls[idRef]
		if !ok {
			return "", false
		}
		return c.Title, true
	})
	t.Cleanup(func() { delete(insertResolvers, "title") })

	ctx := &ResolveContext{Controls: map[string]oscalTypes.Control{
		"ARCH.2.2.1": {ID: "ARCH.2.2.1", Title: "Externe Netzanschlüsse"},
	}}
	got := ResolveInserts("Siehe {{ insert: title, ARCH.2.2.1 }}.", ctx)
	assert.Equal(t, "Siehe Externe Netzanschlüsse.", got)
}

func TestNewResolveContext(t *testing.T) {
	catalog := &oscalTypes.Catalog{
		Params: &[]oscalTypes.Parameter{paramWithLabel("top-prm", "Top Level")},
		Groups: &[]oscalTypes.Group{
			{
				ID:     "GRP.1",
				Title:  "Gruppe 1",
				Params: &[]oscalTypes.Parameter{paramWithLabel("grp-prm", "Group Level")},
				Controls: &[]oscalTypes.Control{
					{
						ID:     "GRP.1.1",
						Title:  "Control 1",
						Params: &[]oscalTypes.Parameter{paramWithLabel("ctl-prm", "Control Level")},
						Controls: &[]oscalTypes.Control{
							{ID: "GRP.1.1.1", Title: "Nested Control"},
						},
					},
				},
				Groups: &[]oscalTypes.Group{
					{ID: "GRP.1.2", Title: "Nested Group"},
				},
			},
		},
		Controls: &[]oscalTypes.Control{
			{ID: "TOP.1", Title: "Top Level Control"},
		},
	}

	ctx := NewResolveContext(catalog)

	assert.Contains(t, ctx.Params, "top-prm")
	assert.Contains(t, ctx.Params, "grp-prm")
	assert.Contains(t, ctx.Params, "ctl-prm")

	assert.Contains(t, ctx.Groups, "GRP.1")
	assert.Contains(t, ctx.Groups, "GRP.1.2")

	assert.Contains(t, ctx.Controls, "GRP.1.1")
	assert.Contains(t, ctx.Controls, "GRP.1.1.1")
	assert.Contains(t, ctx.Controls, "TOP.1")
}

func TestNewResolveContext_NilCatalog(t *testing.T) {
	ctx := NewResolveContext(nil)
	assert.NotNil(t, ctx)
	assert.Empty(t, ctx.Params)
	assert.Empty(t, ctx.Controls)
	assert.Empty(t, ctx.Groups)
}
