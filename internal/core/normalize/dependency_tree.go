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
	"fmt"
	"slices"
	"strings"

	"github.com/package-url/packageurl-go"
)

type TreeNode struct {
	Name     string      `json:"name"`
	Children []*TreeNode `json:"children"`
}

type Tree struct {
	Root    *TreeNode `json:"root"`
	cursors map[string]*TreeNode
}

func newNode(name string) *TreeNode {
	return &TreeNode{
		Name:     name,
		Children: []*TreeNode{},
	}
}

func (tree *Tree) Visitable() ([]string, []string) {

	visited := make(map[string]bool)

	var visit func(node *TreeNode)
	visit = func(node *TreeNode) {
		if node == nil {
			return
		}
		visited[node.Name] = true
		for _, child := range node.Children {
			visit(child)
		}
	}

	visit(tree.Root)
	unvisitable := []string{}
	visitable := []string{}
	for name := range tree.cursors {
		if !visited[name] {
			unvisitable = append(unvisitable, name)
		} else {
			visitable = append(visitable, name)
		}
	}

	return visitable, unvisitable
}

func (tree *Tree) WithMultipleIncomingEdges() []string {
	visited := make(map[string]int)

	var visit func(node *TreeNode)
	visit = func(node *TreeNode) {
		if node == nil {
			return
		}
		visited[node.Name] += 1
		for _, child := range node.Children {
			visit(child)
		}
	}

	visit(tree.Root)

	multipleEdges := []string{}

	for visited, edgeCount := range visited {
		if edgeCount > 1 {
			multipleEdges = append(multipleEdges, visited)
		}
	}

	return multipleEdges
}

func (tree *Tree) addNode(source string, dep string) {
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

// Helper function to detect and cut cycles
func cutCycles(node *TreeNode, visited map[*TreeNode]bool) {
	// Mark the current node as visited
	visited[node] = true

	// Iterate over the children
	for i := 0; i < len(node.Children); i++ {
		child := node.Children[i]
		if visited[child] {
			// If the child is already visited, we have found a cycle
			// Remove the child reference to cut the cycle
			node.Children = append(node.Children[:i], node.Children[i+1:]...)
			i-- // Adjust index due to slice modification
		} else {
			// Recursively check the child
			cutCycles(child, visited)
		}
	}

	// Unmark the current node before returning to allow different paths
	// to explore this node without falsely detecting a cycle
	delete(visited, node)
}

func CalculateDepth(node *TreeNode, currentDepth int, depthMap map[string]int) {
	// check if the child is a VALID PURL - only then increment depth
	_, err := packageurl.FromString(node.Name)
	if err == nil {
		currentDepth++
	}

	if _, ok := depthMap[node.Name]; !ok {
		depthMap[node.Name] = currentDepth
	} else if depthMap[node.Name] > currentDepth {
		// use the shortest path
		depthMap[node.Name] = currentDepth
	}
	for _, child := range node.Children {
		if strings.HasPrefix(child.Name, fmt.Sprintf("%s:", BomTypeVEX)) {
			continue
		}
		CalculateDepth(child, currentDepth, depthMap)
	}
}

type DependencyTree interface {
	GetRef() string
	GetDeps() []string
}

func buildDependencyTree[T DependencyTree](elements []T, root string) Tree {

	treeName := root

	// create a new tree
	tree := Tree{
		Root:    &TreeNode{Name: treeName},
		cursors: make(map[string]*TreeNode),
	}

	tree.cursors[treeName] = tree.Root

	for _, element := range elements {
		ref := element.GetRef()
		for _, d := range element.GetDeps() {
			tree.addNode(ref, d)
		}
	}

	cutCycles(tree.Root, make(map[*TreeNode]bool))

	return tree
}

func escapeNodeID(s string) string {
	// Creates a safe Mermaid node ID by removing special characters
	return strings.NewReplacer("@", "_", ":", "_", "/", "_", ".", "_", "-", "_").Replace(s)
}

func escapeAtSign(pURL string) string {
	// escape @ sign in purl
	return strings.ReplaceAll(pURL, "@", "\\@")
}

func (tree *Tree) RenderToMermaid() string {
	//basic string to tell markdown that we have a mermaid flow chart with given parameters
	mermaidFlowChart := "mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n"

	var builder strings.Builder
	builder.WriteString(mermaidFlowChart)

	var renderPaths func(node *TreeNode)

	var existingPaths = make(map[string]bool)

	renderPaths = func(node *TreeNode) {
		if node == nil {
			return
		}
		// sort the children by name to ensure consistent rendering
		slices.SortStableFunc(node.Children, func(a, b *TreeNode) int {
			return strings.Compare(a.Name, b.Name)
		})
		for _, child := range node.Children {

			fromLabel, err := BeautifyPURL(node.Name)
			if err != nil {
				fromLabel = node.Name
			}
			toLabel, err := BeautifyPURL(child.Name)
			if err != nil {
				toLabel = child.Name
			}
			path := fmt.Sprintf("%s([\"%s\"]) --- %s([\"%s\"])\n",
				escapeNodeID(fromLabel), escapeAtSign(fromLabel), escapeNodeID(toLabel), escapeAtSign(toLabel))
			if existingPaths[path] {
				// skip if path already exists
				continue
			}
			existingPaths[path] = true

			builder.WriteString(path)

			renderPaths(child)
		}
	}

	renderPaths(tree.Root)

	return "```" + builder.String() + "\nclassDef default stroke-width:2px\n```\n"
}

func BuildDependencyTree[T DependencyTree](elements []T, root string) Tree {
	// create a new tree
	return buildDependencyTree(elements, root)

}
