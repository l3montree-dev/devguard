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
package assetversion

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func TestDependencyTree(t *testing.T) {
	t.Run("buildDependencyTree", func(t *testing.T) {
		graph := []models.ComponentDependency{
			{ComponentPurl: nil, DependencyPurl: "a", Depth: 0},
			{ComponentPurl: utils.Ptr("a"), DependencyPurl: "b", Depth: 1},
			{ComponentPurl: utils.Ptr("a"), DependencyPurl: "c", Depth: 1},
			{ComponentPurl: utils.Ptr("b"), DependencyPurl: "d", Depth: 2},
			{ComponentPurl: utils.Ptr("b"), DependencyPurl: "e", Depth: 2},
			{ComponentPurl: utils.Ptr("c"), DependencyPurl: "f", Depth: 3},
			{ComponentPurl: utils.Ptr("c"), DependencyPurl: "g", Depth: 3},
		}
		tree := BuildDependencyTree(graph)

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
	})

	t.Run("test removes cycles", func(t *testing.T) {
		/*
				a
			|       |
			b <---> c # here is the cycle in the tree
		*/
		graph := []models.ComponentDependency{
			{ComponentPurl: nil, DependencyPurl: "a", Depth: 0},
			{ComponentPurl: utils.Ptr("a"), DependencyPurl: "b", Depth: 1},
			{ComponentPurl: utils.Ptr("a"), DependencyPurl: "c", Depth: 1},
			{ComponentPurl: utils.Ptr("b"), DependencyPurl: "c", Depth: 2},
			{ComponentPurl: utils.Ptr("c"), DependencyPurl: "b", Depth: 2}, // closes the cycle
		}
		tree := BuildDependencyTree(graph)

		// expect root node to be created with a single child: a
		if len(tree.Root.Children) != 1 {
			t.Fatalf("expected 1 root child, got %d", len(tree.Root.Children))
		}
		// expect a to have a two children b and c
		if len(tree.Root.Children[0].Children) != 2 {
			t.Fatalf("expected 2 children for a, got %d", len(tree.Root.Children[0].Children))
		}
		// get b and c
		var b, c *treeNode
		for _, child := range tree.Root.Children[0].Children {
			if child.Name == "b" {
				b = child
			} else if child.Name == "c" {
				c = child
			}
		}

		// expect either b or c to have no children
		if len(b.Children) != 0 && len(c.Children) != 0 {
			t.Fatalf("expected either b or c to have no children, got %d and %d", len(b.Children), len(c.Children))
		}

	})
}
