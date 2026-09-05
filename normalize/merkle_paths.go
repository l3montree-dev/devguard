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

package normalize

import (
	"maps"
	"slices"
	"strings"
)

// reverseEdges maps a subtree hash to the hashes of the subtrees that depend on
// it directly. Parents are sorted by component id (then by hash, to break ties
// between two different child sets of the same component) so traversal order is
// deterministic and independent of map iteration.
func (t *MerkleTree) reverseEdges() map[string][]string {
	reverse := make(map[string][]string, len(t.nodes))
	for _, node := range t.nodes {
		for _, child := range node.Children {
			reverse[child] = append(reverse[child], node.SubtreeHash)
		}
	}
	for child := range reverse {
		slices.SortFunc(reverse[child], func(a, b string) int {
			if c := strings.Compare(t.nodes[a].ComponentID, t.nodes[b].ComponentID); c != 0 {
				return c
			}
			return strings.Compare(a, b)
		})
	}
	return reverse
}

// PathsToPURL returns every dependency path from a direct dependency of this
// SBOM down to purl, as component ids. A limit of 0 means unlimited.
//
// Paths are found breadth-first, so shorter paths come first and a limit keeps
// the most direct ones. The root is not part of a path: a path starts at the
// direct dependency that pulls the component in, matching what the old
// info-source-terminated walk produced.
//
// Because the tree is keyed by subtree hash, a component that appears with two
// different child sets is two distinct nodes here, so paths that the purl-keyed
// graph would have conflated stay separate.
func (t *MerkleTree) PathsToPURL(purl string, limit int) []Path {
	targets := t.subtreesFor(purl)
	if len(targets) == 0 {
		return nil
	}

	reverse := t.reverseEdges()

	var paths []Path
	seen := make(map[string]bool)

	type queueItem struct {
		// path holds subtree hashes in reverse: target first, growing rootward
		path   []string
		onPath map[string]bool
	}

	queue := make([]queueItem, 0, len(targets))
	for _, target := range targets {
		queue = append(queue, queueItem{
			path:   []string{target},
			onPath: map[string]bool{target: true},
		})
	}

	for len(queue) > 0 {
		if limit > 0 && len(paths) >= limit {
			break
		}

		current := queue[0]
		queue = queue[1:]
		last := current.path[len(current.path)-1]

		for _, parent := range reverse[last] {
			if current.onPath[parent] {
				// cycle: the tree itself is acyclic, but guard anyway so a
				// malformed edge set cannot loop forever
				continue
			}

			if parent == t.Root {
				// reached the SBOM root, so the path is complete. The root is
				// excluded, leaving the direct dependency at the front.
				if path := t.materializePath(current.path); path != nil {
					key := path.String()
					if !seen[key] {
						seen[key] = true
						paths = append(paths, path)
						if limit > 0 && len(paths) >= limit {
							break
						}
					}
				}
				continue
			}

			// Keep extending even after completing a path: a component can be
			// both a direct dependency and reachable transitively.
			next := make([]string, len(current.path)+1)
			copy(next, current.path)
			next[len(current.path)] = parent
			onPath := make(map[string]bool, len(current.onPath)+1)
			maps.Copy(onPath, current.onPath)
			onPath[parent] = true
			queue = append(queue, queueItem{path: next, onPath: onPath})
		}
	}

	return paths
}

// subtreesFor returns the subtree hashes whose component matches purl, sorted
// so results do not depend on map iteration order. A component can match more
// than one subtree when different SBOM positions give it different child sets.
func (t *MerkleTree) subtreesFor(purl string) []string {
	var targets []string
	for hash, node := range t.nodes {
		if hash == t.Root {
			continue
		}
		if strings.EqualFold(node.ComponentID, purl) {
			targets = append(targets, hash)
		}
	}
	slices.Sort(targets)
	return targets
}

// materializePath turns a rootward list of subtree hashes into a root-to-target
// list of component ids.
func (t *MerkleTree) materializePath(reversed []string) Path {
	path := make(Path, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		node := t.nodes[reversed[i]]
		if node == nil {
			return nil
		}
		path = append(path, node.ComponentID)
	}
	return path
}
