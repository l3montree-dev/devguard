// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"testing"
)

type testNode struct {
	Name string
}

func (n testNode) GetID() string {
	return n.Name
}

func TestDependencyTree(t *testing.T) {
	t.Run("buildDependencyTree", func(t *testing.T) {
		tree := BuildDependencyTree(testNode{Name: "root"}, []testNode{
			testNode{Name: "root"},
			testNode{Name: "a"},
			testNode{Name: "b"},
			testNode{Name: "c"},
			testNode{Name: "d"},
			testNode{Name: "e"},
			testNode{Name: "f"},
			testNode{Name: "g"},
		}, map[string][]string{
			"root": []string{"a"},
			"a":    []string{"b", "c"},
			"b":    []string{"d", "e"},
			"c":    []string{"f", "g"},
		})

		// expect root to have one child: a
		if len(tree.Root.Children) != 1 {
			t.Errorf("expected 1 child for root, got %d", len(tree.Root.Children))
		}

		// Only proceed with further checks if we have at least the expected number of children
		if len(tree.Root.Children) >= 1 {
			// expect a to have two children: b and c
			if len(tree.Root.Children[0].Children) != 2 {
				t.Errorf("expected 2 children for a, got %d", len(tree.Root.Children[0].Children))
			}

			if len(tree.Root.Children[0].Children) >= 2 {
				// expect b to have two children: d and e
				if len(tree.Root.Children[0].Children[0].Children) != 2 {
					t.Errorf("expected 2 children for b, got %d", len(tree.Root.Children[0].Children[0].Children))
				}

				// expect c to have two children: f and g
				if len(tree.Root.Children[0].Children[1].Children) != 2 {
					t.Errorf("expected 2 children for c, got %d", len(tree.Root.Children[0].Children[1].Children))
				}
			}
		}

		if len(tree.Root.Children) >= 1 && len(tree.Root.Children[0].Children) >= 1 && len(tree.Root.Children[0].Children[0].Children) >= 1 {
			// expect d to have no children
			if len(tree.Root.Children[0].Children[0].Children[0].Children) != 0 {
				t.Errorf("expected 0 children for d, got %d", len(tree.Root.Children[0].Children[0].Children[0].Children))
			}
		}
	})

	t.Run("test removes cycles", func(t *testing.T) {
		/*
				a
			|       |
			b <---> c # here is the cycle in the tree
		*/
		graph := []testNode{
			{Name: "root"},
			{Name: "a"},
			{Name: "a"},
			{Name: "b"},
			{Name: "c"},
		}
		tree := BuildDependencyTree(testNode{Name: "root"}, graph, map[string][]string{
			"root": []string{"a"},
			"a":    []string{"b", "c"},
			"b":    []string{"c"},
			"c":    []string{"b"},
		})

		// expect root to have one child: a
		if len(tree.Root.Children) != 1 {
			t.Fatalf("expected 1 child for root, got %d", len(tree.Root.Children))
		}

		// expect a to have two children b and c
		if len(tree.Root.Children[0].Children) != 2 {
			t.Fatalf("expected 2 children for a, got %d", len(tree.Root.Children[0].Children))
		}

		// get b and c
		var b, c *TreeNode[testNode]
		for _, child := range tree.Root.Children[0].Children {
			switch child.ID {
			case "b":
				b = child
			case "c":
				c = child
			}
		}

		// expect either b or c to have no children
		if len(b.Children) != 0 && len(c.Children) != 0 {
			t.Fatalf("expected either b or c to have no children, got %d and %d", len(b.Children), len(c.Children))
		}
	})
}
