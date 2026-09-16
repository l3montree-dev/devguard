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

package transformer

import (
	"github.com/l3montree-dev/devguard/normalize"
	"slices"

	"github.com/google/uuid"
)

// MinimalTree is the flattened shape the frontend renders: the components and
// which of them depend on which. The artifact itself is the empty string.
type MinimalTree struct {
	Nodes        []string            `json:"nodes"`
	Dependencies map[string][]string `json:"dependencies"`
}

// ToMinimalTree flattens the forest for display. Components are keyed by purl,
// so where two SBOMs report different children for one component the display
// shows the union - a rendering choice, not how it is stored.
func ToMinimalTree(f normalize.MerkleForest) MinimalTree {
	nodes := map[string]struct{}{"": {}}
	dependencies := map[string][]string{}

	for _, t := range f {
		for node := range t.MerkleNodes() {
			parent := node.ComponentID
			if node.SubtreeHash == t.Root {
				parent = ""
			} else {
				nodes[parent] = struct{}{}
			}

			for _, childHash := range node.Children {
				child := t.Node(childHash)
				if child == nil {
					continue
				}
				nodes[child.ComponentID] = struct{}{}
				if !slices.Contains(dependencies[parent], child.ComponentID) {
					dependencies[parent] = append(dependencies[parent], child.ComponentID)
				}
			}
		}
	}

	return MinimalTree{Nodes: sortedKeys(nodes), Dependencies: dependencies}
}

// MinimalTreeToPURL returns only the part of the forest leading to purl: every
// ancestor, without enumerating individual paths, so a component reachable many
// ways does not blow up combinatorially. maxDepth of 0 is unlimited.
func MinimalTreeToPURL(f normalize.MerkleForest, purl string, maxDepth int) MinimalTree {
	nodes := map[string]struct{}{}
	dependencies := map[string][]string{}

	for _, t := range f {
		reverse := t.Parents()

		// walk up level by level, so maxDepth counts hops rather than paths
		frontier := t.SubtreesFor(purl)
		seen := map[uuid.UUID]bool{}
		for _, hash := range frontier {
			seen[hash] = true
			if node := t.Node(hash); node != nil {
				nodes[node.ComponentID] = struct{}{}
			}
		}

		for depth := 0; len(frontier) > 0 && (maxDepth == 0 || depth < maxDepth); depth++ {
			var next []uuid.UUID
			for _, childHash := range frontier {
				child := t.Node(childHash)
				if child == nil {
					continue
				}
				for _, parentHash := range reverse[childHash] {
					parent := t.Node(parentHash)
					if parent == nil {
						continue
					}
					parentID := parent.ComponentID
					if parentHash == t.Root {
						parentID = ""
					}
					nodes[parentID] = struct{}{}
					if !slices.Contains(dependencies[parentID], child.ComponentID) {
						dependencies[parentID] = append(dependencies[parentID], child.ComponentID)
					}
					if !seen[parentHash] {
						seen[parentHash] = true
						next = append(next, parentHash)
					}
				}
			}
			frontier = next
		}
	}

	if len(nodes) > 0 {
		nodes[""] = struct{}{}
	}
	return MinimalTree{Nodes: sortedKeys(nodes), Dependencies: dependencies}
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
