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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"
)

// MerkleTree is the content-addressed representation of one SBOM.
//
// It is keyed by subtree hash rather than by component id, which is the whole
// point: hash(component_id, sorted child hashes) covers a component's entire
// child set, so two SBOMs that disagree about a shared component's transitive
// dependencies get different hashes and both descriptions survive. The
// purl-keyed graph could not represent that - one node held one child set, so
// the most recent scan overwrote what every other artifact saw.
//
// A MerkleTree is always exactly one SBOM - one row of the sboms table. There
// are no synthetic `artifact:` or `sbom:` nodes: the artifact name and the
// origin live in that row, and every ComponentID in the tree is a real
// component identity.
//
// The in-memory shape and the stored shape are the same thing: Edges returns
// the rows to persist, MerkleTreeFromEdges reads them back.
type MerkleTree struct {
	// Root is the subtree hash of the SBOM as a whole and identifies it by
	// content: two identical SBOMs anywhere on the instance share this hash.
	Root  string
	nodes map[string]*MerkleNode
}

// MerkleNode is one component together with the exact child set its hash covers.
type MerkleNode struct {
	SubtreeHash string
	ComponentID string
	// Children holds child subtree hashes, sorted, so iteration is
	// deterministic however the tree was built or loaded.
	Children []string
}

// IsLeaf reports whether this component has no dependencies in this SBOM. The
// same component may have children in a different SBOM, under a different
// subtree hash.
func (n *MerkleNode) IsLeaf() bool {
	return len(n.Children) == 0
}

// MerkleEdge is one persisted edge. A component with n children yields n edges
// sharing one SubtreeHash; a leaf yields a single edge with a nil
// DirectDependencySubtreeHash, which is what keeps a leaf's component id
// resolvable - a leaf has no outgoing edge to carry it otherwise.
type MerkleEdge struct {
	SubtreeHash                 string
	ComponentID                 string
	DirectDependencySubtreeHash *string
}

// merkleCycleMarker stands in for a node already on the recursion stack while
// hashing. Dependency graphs can contain cycles and a cycle has no well-defined
// bottom-up hash, so the edge closing the cycle is dropped: recording it would
// make the stored tree cyclic and every downward walk non-terminating.
const merkleCycleMarker = "CYCLE"

// HashSubtree computes the hash covering componentID and its children.
//
// The child set is unordered, so it is sorted first: the same subtree ingested
// twice, in any order, must produce the same hash or deduplication silently
// stops working.
func HashSubtree(componentID string, childSubtreeHashes []string) string {
	sorted := slices.Clone(childSubtreeHashes)
	slices.Sort(sorted)
	// hashed inline rather than via utils.HashString: utils imports normalize,
	// so normalize cannot import utils
	sum := sha256.Sum256([]byte(componentID + "->" + strings.Join(sorted, ";")))
	return hex.EncodeToString(sum[:])
}

// Adjacency is the minimal input needed to hash a document bottom-up: which
// nodes depend on which, and what component identity each node carries.
//
// It is deliberately not a graph type. Parsing a document into this and hashing
// it is the whole ingest path, so there is no second in-memory representation
// of an SBOM to keep in step with the stored one.
type Adjacency struct {
	// Children maps a node id to the node ids it depends on directly.
	Children map[string][]string
	// ComponentIDs maps a node id to its component identity (a purl). A node
	// missing here contributes its own id, which is what happens for documents
	// that identify components by something other than a purl.
	ComponentIDs map[string]string
}

func (a Adjacency) componentID(nodeID string) string {
	if id, ok := a.ComponentIDs[nodeID]; ok && id != "" {
		return id
	}
	return nodeID
}

// BuildMerkleTree converts the subtree below rootID into a content-addressed
// tree.
//
// rootComponentID is the identity the root is hashed under. It exists because
// the root of a parsed document is a synthetic parse artifact rather than a
// real component; passing the artifact's purl (or its name, when it has none)
// keeps every component id in the tree a real component identity.
func BuildMerkleTree(adj Adjacency, rootID, rootComponentID string) *MerkleTree {
	t := &MerkleTree{nodes: make(map[string]*MerkleNode, len(adj.Children))}
	hashes := make(map[string]string, len(adj.Children))
	onStack := make(map[string]bool)
	t.Root = t.build(adj, rootID, rootComponentID, hashes, onStack)
	return t
}

func (t *MerkleTree) build(adj Adjacency, nodeID, componentID string, hashes map[string]string, onStack map[string]bool) string {
	if hash, done := hashes[nodeID]; done {
		return hash
	}
	if onStack[nodeID] {
		return merkleCycleMarker
	}
	onStack[nodeID] = true
	defer delete(onStack, nodeID)

	// sorted so the recursion order does not depend on input ordering
	var childHashes []string
	for _, childID := range slices.Sorted(slices.Values(adj.Children[nodeID])) {
		childHash := t.build(adj, childID, adj.componentID(childID), hashes, onStack)
		if childHash == merkleCycleMarker {
			continue
		}
		// a subtree reachable twice within one parent contributes once
		if !slices.Contains(childHashes, childHash) {
			childHashes = append(childHashes, childHash)
		}
	}
	slices.Sort(childHashes)

	hash := HashSubtree(componentID, childHashes)
	// An identical subtree reached from two different parents resolves to the
	// same hash and the same node - that is the deduplication.
	if _, exists := t.nodes[hash]; !exists {
		t.nodes[hash] = &MerkleNode{SubtreeHash: hash, ComponentID: componentID, Children: childHashes}
	}
	hashes[nodeID] = hash
	return hash
}

// MerkleTreeFromEdges rebuilds a tree from persisted edges. root selects which
// SBOM to materialize, since the edges handed in may cover several.
func MerkleTreeFromEdges(edges []MerkleEdge, root string) (*MerkleTree, error) {
	t := &MerkleTree{Root: root, nodes: make(map[string]*MerkleNode)}

	for _, e := range edges {
		node, exists := t.nodes[e.SubtreeHash]
		if !exists {
			node = &MerkleNode{SubtreeHash: e.SubtreeHash, ComponentID: e.ComponentID}
			t.nodes[e.SubtreeHash] = node
		}
		// a nil child is the leaf marker - that row exists only so the leaf's
		// component id stays resolvable
		if e.DirectDependencySubtreeHash != nil {
			node.Children = append(node.Children, *e.DirectDependencySubtreeHash)
		}
	}

	for _, node := range t.nodes {
		slices.Sort(node.Children)
	}

	if _, ok := t.nodes[root]; !ok && len(edges) > 0 {
		return nil, fmt.Errorf("root subtree %q is not present in the given edges", root)
	}
	return t, nil
}

// Edges renders the tree as rows to persist. Insert them with ON CONFLICT DO
// NOTHING: rows for subtrees the instance has already stored are no-ops, which
// is where the storage saving comes from.
func (t *MerkleTree) Edges() []MerkleEdge {
	edges := make([]MerkleEdge, 0, len(t.nodes))
	for _, node := range t.nodes {
		if node.IsLeaf() {
			edges = append(edges, MerkleEdge{
				SubtreeHash: node.SubtreeHash,
				ComponentID: node.ComponentID,
			})
			continue
		}
		for _, child := range node.Children {
			edges = append(edges, MerkleEdge{
				SubtreeHash:                 node.SubtreeHash,
				ComponentID:                 node.ComponentID,
				DirectDependencySubtreeHash: &child,
			})
		}
	}
	return edges
}

// Node returns the node for a subtree hash, or nil.
func (t *MerkleTree) Node(subtreeHash string) *MerkleNode {
	return t.nodes[subtreeHash]
}

// RootNode returns the root of the SBOM.
func (t *MerkleTree) RootNode() *MerkleNode {
	return t.nodes[t.Root]
}

// Len reports the number of distinct subtrees. This counts subtrees, not
// components: one component appearing with two different child sets is two
// nodes, and one subtree shared by two parents is one node.
func (t *MerkleTree) Len() int {
	return len(t.nodes)
}

// MerkleNodes iterates every distinct subtree in deterministic order.
func (t *MerkleTree) MerkleNodes() iter.Seq[*MerkleNode] {
	return func(yield func(*MerkleNode) bool) {
		for _, hash := range slices.Sorted(maps.Keys(t.nodes)) {
			if !yield(t.nodes[hash]) {
				return
			}
		}
	}
}

// ComponentIDs returns every distinct component in the SBOM, sorted, excluding
// the root - the root is the artifact itself, not one of its dependencies.
func (t *MerkleTree) ComponentIDs() []string {
	seen := make(map[string]struct{}, len(t.nodes))
	for hash, node := range t.nodes {
		if hash == t.Root {
			continue
		}
		seen[node.ComponentID] = struct{}{}
	}
	return slices.Sorted(maps.Keys(seen))
}

// DirectDependencies returns the component ids the SBOM depends on directly.
func (t *MerkleTree) DirectDependencies() []string {
	root := t.RootNode()
	if root == nil {
		return nil
	}
	ids := make([]string, 0, len(root.Children))
	for _, childHash := range root.Children {
		if child := t.nodes[childHash]; child != nil {
			ids = append(ids, child.ComponentID)
		}
	}
	slices.Sort(ids)
	return ids
}
