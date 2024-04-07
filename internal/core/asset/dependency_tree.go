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

	"github.com/l3montree-dev/flawfix/internal/obj"
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
	// add connection
	tree.cursors[source].Children = append(tree.cursors[source].Children, tree.cursors[dep])
}

func buildDependencyTree(elements []obj.Dependency) tree {
	// sort by depth
	slices.SortFunc(elements, func(a, b obj.Dependency) int {
		return a.Depth - b.Depth
	})

	// create a new tree
	tree := tree{
		Root:    &treeNode{Name: "root"},
		cursors: make(map[string]*treeNode),
	}

	tree.cursors["root"] = tree.Root

	for _, element := range elements {
		if element.Depth == 1 {
			tree.addNode("root", element.Source)
		}
		tree.addNode(element.Source, element.Dep)
	}

	return tree
}
