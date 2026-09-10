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
	"bytes"
	"crypto/sha256"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// MerkleRootID is the identity every SBOM root is hashed under. It is a
// sentinel rather than the artifact name on purpose: two artifacts with an
// identical dependency set must reach the same root hash, or the whole tree is
// stored twice. The artifact name lives in the sboms row instead.
const MerkleRootID = "ROOT"

// MerkleTree is one SBOM, keyed by subtree hash rather than by component id.
//
// hash(component_id, sorted child hashes) covers a component's entire child
// set, so SBOMs that disagree about a shared component get different hashes and
// both descriptions survive.
//
// One tree is one row of the sboms table. The artifact name and origin live in
// that row, so every ComponentID here is a real component.
type MerkleTree struct {
	// Root identifies the SBOM by content: identical SBOMs share this hash.
	Root  uuid.UUID
	nodes map[uuid.UUID]*MerkleNode
}

// MerkleNode is one component with the exact child set its hash covers.
type MerkleNode struct {
	SubtreeHash uuid.UUID
	ComponentID string
	// sorted, so iteration is deterministic however the tree was built
	Children []uuid.UUID
}

// IsLeaf reports whether this component has no dependencies in this SBOM. It
// may still have children in another SBOM, under a different subtree hash.
func (n *MerkleNode) IsLeaf() bool {
	return len(n.Children) == 0
}

// MerkleEdge is one persisted edge - a pure pivot between two node hashes. A
// component with n children yields n edges sharing a SubtreeHash; a leaf yields
// none, since its component id is carried by its node row instead.
type MerkleEdge struct {
	SubtreeHash                 uuid.UUID
	DirectDependencySubtreeHash uuid.UUID
}

// merkleCycleMarker stands in for a node already on the recursion stack. A
// cycle has no bottom-up hash, so the edge closing it is dropped - storing it
// would make every downward walk non-terminating. It is not a real hash, so it
// can never collide with one.
var merkleCycleMarker = uuid.UUID{}

// compareHashes orders hashes so child sets and iteration are deterministic.
// uuid.UUID is a byte array, so it has no natural ordering of its own.
func compareHashes(a, b uuid.UUID) int {
	return bytes.Compare(a[:], b[:])
}

func sortHashes(hashes []uuid.UUID) {
	slices.SortFunc(hashes, compareHashes)
}

// HashSubtree computes the hash covering componentID and its children. Children
// are sorted first: the same subtree ingested in any order must hash the same,
// or deduplication silently stops working.
//
// The hash is the leading 128 bits of the sha256, matching utils.HashToUUID.
// That is identity here - a collision would silently serve one subtree in place
// of another - so it is deliberately not truncated further.
func HashSubtree(componentID string, childSubtreeHashes []uuid.UUID) uuid.UUID {
	sorted := slices.Clone(childSubtreeHashes)
	sortHashes(sorted)

	parts := make([]string, 0, len(sorted))
	for _, hash := range sorted {
		parts = append(parts, hash.String())
	}

	// hashed inline rather than via utils.HashToUUID: utils imports normalize,
	// so normalize cannot import utils
	sum := sha256.Sum256([]byte(componentID + "->" + strings.Join(parts, ";")))
	hash, err := uuid.FromBytes(sum[:16])
	if err != nil {
		// unreachable: FromBytes only fails on a slice that is not 16 bytes
		panic(fmt.Sprintf("could not build subtree hash: %v", err))
	}
	return hash
}

// Adjacency is the minimal input needed to hash a document bottom-up. Refs are
// whatever handle the document uses to cross-reference components (a CycloneDX
// bom-ref, say); they are a parsing detail and never reach the database.
//
// Deliberately not a graph type: parsing into this and hashing it is the whole
// ingest path, so there is no second in-memory SBOM representation to keep in
// step with the stored one.
type Adjacency struct {
	// Children maps a ref to the refs it depends on directly.
	Children map[string][]string
	// ComponentIDs maps a ref to its component identity (a purl). A ref missing
	// here contributes itself, as happens for documents that identify
	// components by something other than a purl.
	ComponentIDs map[string]string
}

func (a Adjacency) componentID(ref string) string {
	if id, ok := a.ComponentIDs[ref]; ok && id != "" {
		return id
	}
	return ref
}

// BuildMerkleTree converts the document below rootRef into a content-addressed
// tree.
//
// rootComponentID is the identity the root is hashed under. A document's root
// is a parse artifact, not a real component, so passing the artifact's purl (or
// its name, when it has none) keeps every stored component id a real one.
func BuildMerkleTree(adj Adjacency, rootRef, rootComponentID string) *MerkleTree {
	t := &MerkleTree{nodes: make(map[uuid.UUID]*MerkleNode, len(adj.Children))}
	hashes := make(map[string]uuid.UUID, len(adj.Children))
	onStack := make(map[string]bool)
	t.Root = t.build(adj, rootRef, rootComponentID, hashes, onStack)
	return t
}

func (t *MerkleTree) build(adj Adjacency, ref, rootComponentID string, hashes map[string]uuid.UUID, onStack map[string]bool) uuid.UUID {
	if hash, done := hashes[ref]; done {
		return hash
	}
	if onStack[ref] {
		return merkleCycleMarker
	}
	onStack[ref] = true
	defer delete(onStack, ref)

	// sorted so the recursion order does not depend on input ordering
	var childHashes []uuid.UUID
	for _, childRef := range slices.Sorted(slices.Values(adj.Children[ref])) {
		childHash := t.build(adj, childRef, adj.componentID(childRef), hashes, onStack)
		if childHash == merkleCycleMarker {
			continue
		}
		// a subtree reachable twice within one parent contributes once
		if !slices.Contains(childHashes, childHash) {
			childHashes = append(childHashes, childHash)
		}
	}
	sortHashes(childHashes)

	hash := HashSubtree(rootComponentID, childHashes)
	// the same subtree reached from two parents resolves to a single node
	if _, exists := t.nodes[hash]; !exists {
		t.nodes[hash] = &MerkleNode{SubtreeHash: hash, ComponentID: rootComponentID, Children: childHashes}
	}
	hashes[ref] = hash
	return hash
}

// MerkleTreeFromNodesAndEdges rebuilds a tree from persisted rows. root selects
// which SBOM to materialize, since the rows handed in may cover several.
//
// Nodes carry the component ids and edges only the shape, so a leaf is a node
// with no outgoing edge rather than an edge with a nil child. Children on the
// nodes handed in are ignored - the edges are the authority on shape.
func MerkleTreeFromNodesAndEdges(nodes []MerkleNode, edges []MerkleEdge, root uuid.UUID) (*MerkleTree, error) {
	t := &MerkleTree{Root: root, nodes: make(map[uuid.UUID]*MerkleNode, len(nodes))}

	for _, n := range nodes {
		t.nodes[n.SubtreeHash] = &MerkleNode{SubtreeHash: n.SubtreeHash, ComponentID: n.ComponentID}
	}

	for _, e := range edges {
		node, ok := t.nodes[e.SubtreeHash]
		if !ok {
			return nil, fmt.Errorf("edge references subtree %s with no node row", e.SubtreeHash)
		}
		node.Children = append(node.Children, e.DirectDependencySubtreeHash)
	}

	for _, node := range t.nodes {
		sortHashes(node.Children)
	}

	if _, ok := t.nodes[root]; !ok && len(nodes) > 0 {
		return nil, fmt.Errorf("root subtree %s is not present in the given nodes", root)
	}
	return t, nil
}

// Edges renders the tree's shape as rows to persist. Leaves contribute nothing:
// they have no outgoing edge, and Nodes carries their component id.
//
// Insert them with ON CONFLICT DO NOTHING: rows for subtrees the instance has
// already stored are no-ops, which is where the storage saving comes from.
func (t *MerkleTree) Edges() []MerkleEdge {
	edges := make([]MerkleEdge, 0, len(t.nodes))
	for _, node := range t.nodes {
		for _, child := range node.Children {
			edges = append(edges, MerkleEdge{
				SubtreeHash:                 node.SubtreeHash,
				DirectDependencySubtreeHash: child,
			})
		}
	}
	return edges
}

// Nodes renders the tree's component identities as rows to persist, one per
// distinct subtree. Insert these before Edges: an edge references two of them.
func (t *MerkleTree) Nodes() []MerkleNode {
	nodes := make([]MerkleNode, 0, len(t.nodes))
	for _, node := range t.nodes {
		nodes = append(nodes, MerkleNode{SubtreeHash: node.SubtreeHash, ComponentID: node.ComponentID})
	}
	return nodes
}

// Node returns the node for a subtree hash, or nil.
func (t *MerkleTree) Node(subtreeHash uuid.UUID) *MerkleNode {
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
		hashes := slices.Collect(maps.Keys(t.nodes))
		sortHashes(hashes)
		for _, hash := range hashes {
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

// MerkleForest is a set of SBOMs scanned together - in practice every origin of
// one artifact, or every SBOM of an asset version.
//
// The trees stay separate rather than being merged into one graph: two origins
// may legitimately disagree about a shared component, and both answers matter
// when reporting where a vulnerability comes from.
type MerkleForest []*MerkleTree

// ComponentIDs returns every distinct component across the forest, sorted.
func (f MerkleForest) ComponentIDs() []string {
	seen := map[string]struct{}{}
	for _, tree := range f {
		for _, id := range tree.ComponentIDs() {
			seen[id] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// PathsToPURL returns the dependency paths to purl across every SBOM, deduped.
// A limit of 0 means unlimited; otherwise it caps the total, keeping the most
// direct paths first.
func (f MerkleForest) PathsToPURL(purl string, limit int) []Path {
	var paths []Path
	seen := map[string]bool{}

	for _, tree := range f {
		for _, path := range tree.PathsToPURL(purl, limit) {
			key := path.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			paths = append(paths, path)
			if limit > 0 && len(paths) >= limit {
				return paths
			}
		}
	}
	return paths
}

// ComponentsInMultipleSBOMs returns components that more than one SBOM in the
// forest reports. Such a component cannot be marked fixed off a single scan:
// one source dropping it says nothing about the others.
func (f MerkleForest) ComponentsInMultipleSBOMs() []string {
	counts := map[string]int{}
	for _, tree := range f {
		for _, id := range tree.ComponentIDs() {
			counts[id]++
		}
	}

	var shared []string
	for id, count := range counts {
		if count > 1 {
			shared = append(shared, id)
		}
	}
	slices.Sort(shared)
	return shared
}
