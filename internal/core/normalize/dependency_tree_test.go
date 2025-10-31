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
	Dep  string
}

func (n testNode) GetRef() string {
	return n.Name
}

func (n testNode) GetDeps() []string {
	return []string{n.Dep}
}

func TestDependencyTree(t *testing.T) {
	t.Run("buildDependencyTree", func(t *testing.T) {
		graph := []testNode{
			{Name: "root", Dep: "a"},
			{Name: "a", Dep: "b"},
			{Name: "a", Dep: "c"},
			{Name: "b", Dep: "d"},
			{Name: "b", Dep: "e"},
			{Name: "c", Dep: "f"},
			{Name: "c", Dep: "g"},
		}
		tree := BuildDependencyTree(graph, "root")

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
			{Name: "root", Dep: "a"},
			{Name: "a", Dep: "b"},
			{Name: "a", Dep: "c"},
			{Name: "b", Dep: "c"},
			{Name: "c", Dep: "b"},
		}
		tree := BuildDependencyTree(graph, "root")

		// expect root to have one child: a
		if len(tree.Root.Children) != 1 {
			t.Fatalf("expected 1 child for root, got %d", len(tree.Root.Children))
		}

		// expect a to have two children b and c
		if len(tree.Root.Children[0].Children) != 2 {
			t.Fatalf("expected 2 children for a, got %d", len(tree.Root.Children[0].Children))
		}

		// get b and c
		var b, c *TreeNode
		for _, child := range tree.Root.Children[0].Children {
			switch child.Name {
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
func TestCalculateDepth(t *testing.T) {
	t.Run("calculateDepth with valid tree", func(t *testing.T) {
		root := &TreeNode{Name: "root"}
		a := &TreeNode{Name: "pkg:golang/a"}
		b := &TreeNode{Name: "pkg:golang/b"}
		c := &TreeNode{Name: "pkg:golang/c"}
		d := &TreeNode{Name: "pkg:golang/d"}

		root.Children = []*TreeNode{a}
		a.Children = []*TreeNode{b, c}
		b.Children = []*TreeNode{d}

		depthMap := make(map[string]int)
		CalculateDepth(root, 0, depthMap)

		expectedDepths := map[string]int{
			"root":         0,
			"pkg:golang/a": 1,
			"pkg:golang/b": 2,
			"pkg:golang/c": 2,
			"pkg:golang/d": 3,
		}

		for node, expectedDepth := range expectedDepths {
			if depthMap[node] != expectedDepth {
				t.Errorf("expected depth of %s to be %d, got %d", node, expectedDepth, depthMap[node])
			}
		}
	})

	t.Run("calculateDepth with invalid PURL", func(t *testing.T) {
		root := &TreeNode{Name: "root"}
		a := &TreeNode{Name: "go.mod"}
		b := &TreeNode{Name: "tmp"}
		c := &TreeNode{Name: "pkg:golang/github.com/gorilla/websocket"}

		root.Children = []*TreeNode{a}
		a.Children = []*TreeNode{b}
		b.Children = []*TreeNode{c}

		depthMap := make(map[string]int)
		CalculateDepth(root, 0, depthMap)

		expectedDepths := map[string]int{
			"root":   0,
			"go.mod": 0,
			"tmp":    0,
			"pkg:golang/github.com/gorilla/websocket": 1,
		}

		for node, expectedDepth := range expectedDepths {
			if depthMap[node] != expectedDepth {
				t.Errorf("expected depth of %s to be %d, got %d", node, expectedDepth, depthMap[node])
			}
		}
	})

	t.Run("calculateDepth with empty tree", func(t *testing.T) {
		root := &TreeNode{Name: "root"}

		depthMap := make(map[string]int)
		CalculateDepth(root, 0, depthMap)

		if len(depthMap) != 1 || depthMap["root"] != 0 {
			t.Errorf("expected depth map to contain only root with depth 0, got %v", depthMap)
		}
	})
}
