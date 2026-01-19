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
	"log/slog"
	"slices"
	"strings"
)

type TreeNode[Element Node] struct {
	element  Element
	ID       string               `json:"name"`
	Children []*TreeNode[Element] `json:"children"`
}

type Tree[Element Node] struct {
	Root    *TreeNode[Element] `json:"root"`
	cursors map[string]*TreeNode[Element]
}

type NodeChangeType string

const (
	NodeAdded   NodeChangeType = "added"
	NodeRemoved NodeChangeType = "removed"
)

type EdgeChangeType string

const (
	EdgeAdded   EdgeChangeType = "added"
	EdgeRemoved EdgeChangeType = "removed"
)

type NodeDiff[Element Node] struct {
	ID   string
	Type NodeChangeType
	Node *TreeNode[Element]
}

type EdgeDiff struct {
	From string
	To   string
	Type EdgeChangeType
}

func flatten[E Node](
	n *TreeNode[E],
	nodes map[string]*TreeNode[E],
	edges map[[2]string]struct{},
	parent *TreeNode[E],
) {
	if n == nil {
		return
	}

	nodes[n.ID] = n

	if parent != nil {
		edges[[2]string{parent.ID, n.ID}] = struct{}{}
	}

	for _, c := range n.Children {
		flatten(c, nodes, edges, n)
	}
}

type TreeDiff[Element Node] struct {
	Nodes []NodeDiff[Element]
	Edges []EdgeDiff
}

func diffNodes[E Node](
	a, b map[string]*TreeNode[E],
) []NodeDiff[E] {

	var out []NodeDiff[E]

	for id, n := range a {
		if _, ok := b[id]; !ok {
			out = append(out, NodeDiff[E]{
				ID:   id,
				Type: NodeRemoved,
				Node: n,
			})
		}
	}

	for id, n := range b {
		if _, ok := a[id]; !ok {
			out = append(out, NodeDiff[E]{
				ID:   id,
				Type: NodeAdded,
				Node: n,
			})
		}
	}

	return out
}

func diffEdges(
	a, b map[[2]string]struct{},
) []EdgeDiff {

	var out []EdgeDiff

	for e := range a {
		if _, ok := b[e]; !ok {
			out = append(out, EdgeDiff{
				From: e[0],
				To:   e[1],
				Type: EdgeRemoved,
			})
		}
	}

	for e := range b {
		if _, ok := a[e]; !ok {
			out = append(out, EdgeDiff{
				From: e[0],
				To:   e[1],
				Type: EdgeAdded,
			})
		}
	}

	return out
}

func Diff[E Node](a, b *Tree[E]) TreeDiff[E] {
	aNodes := map[string]*TreeNode[E]{}
	bNodes := map[string]*TreeNode[E]{}
	aEdges := map[[2]string]struct{}{}
	bEdges := map[[2]string]struct{}{}

	flatten(a.Root, aNodes, aEdges, nil)
	flatten(b.Root, bNodes, bEdges, nil)

	return TreeDiff[E]{
		Nodes: diffNodes(aNodes, bNodes),
		Edges: diffEdges(aEdges, bEdges),
	}
}

func newNode[Element Node](el Element) *TreeNode[Element] {
	return &TreeNode[Element]{
		ID:       el.GetID(),
		element:  el,
		Children: []*TreeNode[Element]{},
	}
}

func (tree *Tree[Element]) ReplaceRoot(node Element) {
	originalChildren := tree.Root.Children

	newRootNode := newNode(node)
	newRootNode.Children = originalChildren
	tree.cursors[node.GetID()] = newRootNode
	tree.Root = newRootNode
}

func (tree *Tree[Element]) AddChild(parent *TreeNode[Element], child *TreeNode[Element]) {
	// we actually get two tree nodes here
	// this means they might contain children
	parent.Children = append(parent.Children, child)
	tree.addNode(child)
}

func (tree *Tree[Element]) AddDirectChildWhichInheritsChildren(parent Element, child Element) {
	// find parent node
	parentNode, exists := tree.cursors[parent.GetID()]
	if !exists {
		return
	}

	// create new child node
	childNode := newNode(child)
	// inherit children from parent
	childNode.Children = parentNode.Children

	// set parent's children to only the new child
	parentNode.Children = []*TreeNode[Element]{childNode}
	tree.cursors[child.GetID()] = childNode
}

func (tree *Tree[Element]) AddSourceChildrenToTarget(source *TreeNode[Element], target *TreeNode[Element]) {
	// source children are added to target children
	// avoiding duplicates
	existingChildren := make(map[string]bool)
	for _, child := range target.Children {
		existingChildren[child.ID] = true
	}

	for _, child := range source.Children {
		if !existingChildren[child.ID] {
			target.Children = append(target.Children, child)
			existingChildren[child.ID] = true
			tree.addNode(child)
		}
	}
}

func (tree *Tree[Element]) addNode(node *TreeNode[Element]) {
	tree.cursors[node.ID] = node
	// add all children recursively
	for _, child := range node.Children {
		tree.addNode(child)
	}
}

func (tree *Tree[Element]) ReplaceNode(old *TreeNode[Element], new *TreeNode[Element]) {
	// find parent of old node
	for _, node := range tree.cursors {
		for i, child := range node.Children {
			if child.ID == old.ID {
				// replace old with new
				node.Children[i] = new
			}
		}
	}
	tree.addNode(new)
}

func (tree *Tree[Element]) ReplaceSubtree(other *TreeNode[Element]) {
	var overlay func(node *TreeNode[Element])

	overlay = func(node *TreeNode[Element]) {
		if node == nil {
			return
		}
		if node.ID == other.ID {

			// replace by other nodes children
			node.Children = other.Children
			// ensure all children are in the tree cursors
			for _, child := range other.Children {
				tree.addNode(child)
			}
		}
		for _, child := range node.Children {
			overlay(child)
		}
	}

	overlay(tree.Root)
}

func (tree *Tree[Element]) Visitable() ([]string, []string) {
	visited := make(map[string]bool)

	var visit func(node *TreeNode[Element])
	visit = func(node *TreeNode[Element]) {
		if node == nil {
			return
		}
		visited[node.ID] = true
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

type FlatTree struct {
	Nodes []string
	Edges [][2]string
}

func (tree *Tree[Element]) NodeIDsAndEdges() FlatTree {
	visited := make(map[string]bool)

	var nodes []string
	var edges [][2]string

	var visit func(node *TreeNode[Element])
	visit = func(node *TreeNode[Element]) {
		if node == nil {
			return
		}
		if visited[node.ID] {
			return // Already visited, avoid infinite loops
		}
		visited[node.ID] = true
		nodes = append(nodes, node.ID)
		for _, child := range node.Children {
			edges = append(edges, [2]string{node.ID, child.ID})
			visit(child)
		}
	}

	visit(tree.Root)
	return FlatTree{
		Nodes: nodes,
		Edges: edges,
	}
}

func (tree *Tree[Element]) addElement(source Element, dep Element) {
	// check if source does exist
	if _, ok := tree.cursors[source.GetID()]; !ok {
		tree.cursors[source.GetID()] = newNode(source)
	}
	// check if dep does already exist
	if _, ok := tree.cursors[dep.GetID()]; !ok {
		tree.cursors[dep.GetID()] = newNode(dep)
	}

	// check if connection does already exist
	for _, child := range tree.cursors[source.GetID()].Children {
		if child.ID == dep.GetID() {
			return
		}
	}

	tree.cursors[source.GetID()].Children = append(tree.cursors[source.GetID()].Children, tree.cursors[dep.GetID()])
}

// Helper function to detect and cut cycles
func cutCycles[Element Node](node *TreeNode[Element], visited map[*TreeNode[Element]]bool) {
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

type Node interface {
	GetID() string
}

func BuildDependencyTree[Element Node](root Element, elements []Element, depMap map[string][]string) Tree[Element] {
	// create a new tree
	rootNode := newNode(root)
	tree := Tree[Element]{
		Root: rootNode,
		cursors: map[string]*TreeNode[Element]{
			root.GetID(): rootNode,
		},
	}
	// build a data map
	elementMap := make(map[string]Element)
	for _, element := range elements {
		elementMap[element.GetID()] = element
	}
	elementMap[root.GetID()] = root

	for _, element := range elementMap {
		ref := element.GetID()
		depMapEntry, ok := depMap[ref]
		if !ok {
			continue
		}
		for _, d := range depMapEntry {
			if dep, ok := elementMap[d]; ok {
				tree.addElement(element, dep)
			} else {
				// dependency not found in element map, create a placeholder node
				slog.Info("not found")
			}
		}
	}
	cutCycles(tree.Root, make(map[*TreeNode[Element]]bool))
	return tree
}

func escapeNodeID(s string) string {
	if s == "" {
		return "root"
	}
	// Creates a safe Mermaid node ID by removing special characters
	return strings.NewReplacer("@", "_", ":", "_", "/", "_", ".", "_", "-", "_").Replace(s)
}

func escapeAtSign(pURL string) string {
	if pURL == "" {
		return "root"
	}
	// escape @ sign in purl
	return strings.ReplaceAll(pURL, "@", "\\@")
}

func (tree *Tree[Data]) Reachable(id string) bool {
	var found bool
	var search func(node *TreeNode[Data])
	search = func(node *TreeNode[Data]) {
		if node == nil || found {
			return
		}
		if node.ID == id {
			found = true
			return
		}
		for _, child := range node.Children {
			search(child)
		}
	}

	search(tree.Root)
	return found
}

func (tree *Tree[Data]) RenderToMermaid() string {
	//basic string to tell markdown that we have a mermaid flow chart with given parameters
	mermaidFlowChart := "mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n"

	var builder strings.Builder
	builder.WriteString(mermaidFlowChart)

	var renderPaths func(node *TreeNode[Data])

	var existingPaths = make(map[string]bool)

	renderPaths = func(node *TreeNode[Data]) {
		if node == nil {
			return
		}
		// sort the children by name to ensure consistent rendering
		slices.SortStableFunc(node.Children, func(a, b *TreeNode[Data]) int {
			return strings.Compare(a.ID, b.ID)
		})
		for _, child := range node.Children {
			fromLabel, err := BeautifyPURL(node.ID)
			if err != nil {
				fromLabel = node.ID
			}
			toLabel, err := BeautifyPURL(child.ID)
			if err != nil {
				toLabel = child.ID
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

// FindAllPathsTo finds all paths from root to the specified node ID.
// Returns a slice of paths, where each path is a slice of node IDs from root to target.
func (tree *Tree[Data]) FindAllPathsTo(targetID string) [][]string {
	var paths [][]string

	var visit func(node *TreeNode[Data], currentPath []string)
	visit = func(node *TreeNode[Data], currentPath []string) {
		if node == nil {
			return
		}

		// Check for cycles
		if slices.Contains(currentPath, node.ID) {
			return
		}

		// Add current node to path
		newPath := append([]string{}, currentPath...)
		newPath = append(newPath, node.ID)

		// Found target
		if node.ID == targetID {
			paths = append(paths, newPath)
			return
		}

		// Continue to children
		for _, child := range node.Children {
			visit(child, newPath)
		}
	}

	visit(tree.Root, []string{})
	return paths
}

// ExtractSubtree returns all node IDs reachable from a starting node.
func (tree *Tree[Data]) ExtractSubtree(startID string) []string {
	startNode, exists := tree.cursors[startID]
	if !exists {
		return nil
	}

	reachable := make(map[string]bool)
	var visit func(node *TreeNode[Data])
	visit = func(node *TreeNode[Data]) {
		if node == nil || reachable[node.ID] {
			return
		}
		reachable[node.ID] = true
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(startNode)

	result := make([]string, 0, len(reachable))
	for nodeID := range reachable {
		result = append(result, nodeID)
	}
	return result
}

// GetNode returns the tree node for the given ID, or nil if not found.
func (tree *Tree[Data]) GetNode(id string) *TreeNode[Data] {
	return tree.cursors[id]
}
