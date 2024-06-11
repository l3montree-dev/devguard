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
	"slices"

	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type treeNode struct {
	Name     string      `json:"name"`
	Children []*treeNode `json:"children"`
}

type tree struct {
	Root    *treeNode `json:"root"`
	cursors map[string]*treeNode
}

func newNode(name string) *treeNode {
	return &treeNode{
		Name:     name,
		Children: []*treeNode{},
	}
}

func (tree *tree) addNode(source string, dep string) {
	// check if source does exist
	if _, ok := tree.cursors[source]; !ok {
		tree.cursors[source] = newNode(source)
	}
	// check if dep does already exist
	if _, ok := tree.cursors[dep]; !ok {
		tree.cursors[dep] = newNode(dep)
	}

	// check if connection does already exist
	for _, child := range tree.cursors[source].Children {
		if child.Name == dep {
			return
		}
	}

	tree.cursors[source].Children = append(tree.cursors[source].Children, tree.cursors[dep])
}

func removeEdge(node *treeNode, childName string) {
	for i, child := range node.Children {
		if child.Name == childName {
			node.Children = append(node.Children[:i], node.Children[i+1:]...)
			return
		}
	}
}

func cutCycles(tree *tree, removedEdges map[string][]string) {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(node *treeNode) bool

	dfs = func(node *treeNode) bool {
		if visited[node.Name] == false {
			// Mark the current node as visited and part of recursion stack
			visited[node.Name] = true
			recStack[node.Name] = true

			// Recur for all the vertices adjacent to this vertex
			for _, child := range node.Children {
				if !visited[child.Name] && dfs(child) {
					return true
				} else if recStack[child.Name] {
					// If the node is in the recStack, then there is a cycle
					// Remove the edge that closes the cycle
					removeEdge(node, child.Name)
					removedEdges[node.Name] = append(removedEdges[node.Name], child.Name)
					return true
				}
			}

		}
		recStack[node.Name] = false // remove the vertex from recursion stack
		return false
	}

	// Iterate over all nodes in the graph and apply DFS
	for _, node := range tree.cursors {
		if !visited[node.Name] {
			dfs(node)
		}
	}
}

func buildDependencyTree(elements []models.ComponentDependency) (tree, map[string][]string) {
	// sort by depth
	slices.SortFunc(elements, func(a, b models.ComponentDependency) int {
		return a.Depth - b.Depth
	})

	// create a new tree
	tree := tree{
		Root:    &treeNode{Name: "root"},
		cursors: make(map[string]*treeNode),
	}

	tree.cursors["root"] = tree.Root

	for _, element := range elements {
		if element.ComponentPurlOrCpe == nil {
			tree.addNode("root", element.DependencyPurlOrCpe)
		} else {
			tree.addNode(*element.ComponentPurlOrCpe, element.DependencyPurlOrCpe)
		}
	}

	// remove cycles
	removedEdges := make(map[string][]string)
	cutCycles(&tree, removedEdges)

	return tree, removedEdges
}
