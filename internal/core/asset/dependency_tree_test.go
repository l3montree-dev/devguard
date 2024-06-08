// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
package asset

import (
	"testing"

	"github.com/l3montree-dev/flawfix/internal/database/models"
)

func TestDependencyTree(t *testing.T) {
	graph := []models.ComponentDependency{
		{ComponentPurlOrCpe: "a", DependencyPurlOrCpe: "b", Depth: 1},
		{ComponentPurlOrCpe: "a", DependencyPurlOrCpe: "c", Depth: 1},
		{ComponentPurlOrCpe: "b", DependencyPurlOrCpe: "d", Depth: 2},
		{ComponentPurlOrCpe: "b", DependencyPurlOrCpe: "e", Depth: 2},
		{ComponentPurlOrCpe: "c", DependencyPurlOrCpe: "f", Depth: 3},
		{ComponentPurlOrCpe: "c", DependencyPurlOrCpe: "g", Depth: 3},
	}
	tree := buildDependencyTree(graph)

	// expect root node to be created with a single child: a
	if len(tree.Root.Children) != 1 {
		t.Errorf("expected 1 root child, got %d", len(tree.Root.Children))
	}
	// expect a to have two children: b and c
	if len(tree.Root.Children[0].Children) != 2 {
		t.Errorf("expected 2 children for a, got %d", len(tree.Root.Children[0].Children))
	}

	// expect b to have two children: d and e
	if len(tree.Root.Children[0].Children[0].Children) != 2 {
		t.Errorf("expected 2 children for b, got %d", len(tree.Root.Children[0].Children[0].Children))
	}

	// expect c to have two children: f and g
	if len(tree.Root.Children[0].Children[1].Children) != 2 {
		t.Errorf("expected 2 children for c, got %d", len(tree.Root.Children[0].Children[1].Children))
	}

	// expect d to have no children
	if len(tree.Root.Children[0].Children[0].Children[0].Children) != 0 {
		t.Errorf("expected 0 children for d, got %d", len(tree.Root.Children[0].Children[0].Children[0].Children))
	}
}
