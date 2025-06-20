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

package assetversion

import (
	"fmt"
	"slices"
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
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

// Helper function to detect and cut cycles
func cutCycles(node *treeNode, visited map[*treeNode]bool) {
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

func CalculateDepth(node *treeNode, currentDepth int, depthMap map[string]int) {
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
		CalculateDepth(child, currentDepth, depthMap)
	}
}

func buildDependencyTree(treeName string, elements []models.ComponentDependency) tree {
	// create a new tree
	tree := tree{
		Root:    &treeNode{Name: treeName},
		cursors: make(map[string]*treeNode),
	}

	tree.cursors[treeName] = tree.Root

	for _, element := range elements {
		if element.ComponentPurl == nil {
			tree.addNode(treeName, element.DependencyPurl)
		} else {
			tree.addNode(*element.ComponentPurl, element.DependencyPurl)
		}
	}

	cutCycles(tree.Root, make(map[*treeNode]bool))

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

func (tree *tree) RenderToMermaid() string {
	//basic string to tell markdown that we have a mermaid flow chart with given parameters
	mermaidFlowChart := "mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n"

	var builder strings.Builder
	builder.WriteString(mermaidFlowChart)

	var renderPaths func(node *treeNode)

	var existingPaths = make(map[string]bool)

	renderPaths = func(node *treeNode) {
		if node == nil {
			return
		}
		// sort the children by name to ensure consistent rendering
		slices.SortStableFunc(node.Children, func(a, b *treeNode) int {
			return strings.Compare(a.Name, b.Name)
		})
		for _, child := range node.Children {

			fromLabel, err := utils.BeautifyPURL(node.Name)
			if err != nil {
				fromLabel = node.Name
			}
			toLabel, err := utils.BeautifyPURL(child.Name)
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

func GetComponentDepth(elements []models.ComponentDependency) map[string]int {
	tree := BuildDependencyTree(elements)
	// calculate the depth for each node
	depthMap := make(map[string]int)
	CalculateDepth(tree.Root, -1, depthMap) // first purl will be the application itself. whenever calculate depth sees a purl, it increments the depth.
	// so the application itself will be at depth 0, the first dependency at depth 1, and so on.
	return depthMap
}

func buildDependencyTreePerScanner(elements []models.ComponentDependency) map[string]tree {
	// create a new tree
	res := make(map[string]tree)
	scannerDependencyMap := make(map[string][]models.ComponentDependency)
	for _, element := range elements {
		scannerIDs := element.ScannerIDs
		// split at whitespace
		scannerIDsList := strings.Fields(scannerIDs)
		for _, scannerID := range scannerIDsList {
			if _, ok := scannerDependencyMap[scannerID]; !ok {
				scannerDependencyMap[scannerID] = make([]models.ComponentDependency, 0)
			}
			scannerDependencyMap[scannerID] = append(scannerDependencyMap[scannerID], element)
		}
	}

	for scannerID, elements := range scannerDependencyMap {
		// group the elements by scanner id and build the dependency trees.
		// for each scanner
		tree := buildDependencyTree(scannerID, elements)
		res[scannerID] = tree
	}

	return res
}

func mergeDependencyTrees(trees map[string]tree) tree {
	// create a new tree
	tree := tree{
		Root:    &treeNode{Name: "root"},
		cursors: make(map[string]*treeNode),
	}

	tree.cursors["root"] = tree.Root
	// if we have the sca and container scanning tree, remove the container scanning tree: For most applications the sca tree is much more detailed.
	if _, ok := trees["github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning"]; ok {
		// check if the sca tree exists
		if _, ok := trees["github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca"]; ok {
			// remove the container scanning tree
			delete(trees, "github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning")
		}
	}

	for _, t := range trees {
		// merge the trees
		tree.Root.Children = append(tree.Root.Children, t.Root)
		// merge the cursors
		for k, v := range t.cursors {
			if _, ok := tree.cursors[k]; !ok {
				tree.cursors[k] = v
			}
		}
	}

	// check if the root node only has a single child (single scanner)
	// if so, remove the root node.
	if len(tree.Root.Children) == 1 {
		tree.Root = tree.Root.Children[0]
	}
	// check if the root node still has a single child (single inspected meta file by the scanner) - if so, lets keep the single metafile (like go.mod) as root
	if len(tree.Root.Children) == 1 {
		tree.Root = tree.Root.Children[0]
	}

	return tree
}

func BuildDependencyTree(elements []models.ComponentDependency) tree {
	// create a new tree
	treeMap := buildDependencyTreePerScanner(elements)

	// merge the trees
	return mergeDependencyTrees(treeMap)
}
