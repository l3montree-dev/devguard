package normalize

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adjacency builds an Adjacency where every node's component identity is its
// own id, which is how a purl-identified document parses.
func adjacency(children map[string][]string) Adjacency {
	return Adjacency{Children: children, ComponentIDs: map[string]string{}}
}

// merkleParseRoot mirrors the synthetic root ref the CycloneDX parser uses, so
// these tests build trees the same shape the real ingest path produces.
const merkleParseRoot = "\x00sbom-root"

func buildTree(children map[string][]string, artifactName string) *MerkleTree {
	return BuildMerkleTree(Adjacency{Children: children}, merkleParseRoot, artifactName)
}

func edgeKey(e MerkleEdge) [2]string {
	return [2]string{e.SubtreeHash.String(), e.DirectDependencySubtreeHash.String()}
}

func edgeSet(edges []MerkleEdge) map[[2]string]struct{} {
	set := make(map[[2]string]struct{}, len(edges))
	for _, e := range edges {
		set[edgeKey(e)] = struct{}{}
	}
	return set
}

// nodesFor returns every node covering componentID. One component appears more
// than once when two SBOMs disagree about its children.
func nodesFor(tree *MerkleTree, componentID string) []MerkleNode {
	var nodes []MerkleNode
	for _, n := range tree.Nodes() {
		if n.ComponentID == componentID {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// rowsFor returns the edges leaving every node that covers componentID. A leaf
// has none - its identity is carried by its node row.
func rowsFor(tree *MerkleTree, componentID string) []MerkleEdge {
	var rows []MerkleEdge
	for _, n := range nodesFor(tree, componentID) {
		for _, e := range tree.Edges() {
			if e.SubtreeHash == n.SubtreeHash {
				rows = append(rows, e)
			}
		}
	}
	return rows
}

func TestBuildMerkleTree(t *testing.T) {
	t.Run("a leaf gets a node but no edge, and stays resolvable through it", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/leaf@1.0.0"},
		}), "src", "my-artifact")

		nodes := nodesFor(tree, "pkg:npm/leaf@1.0.0")
		require.Len(t, nodes, 1, "a leaf must have a node of its own")
		assert.Empty(t, rowsFor(tree, "pkg:npm/leaf@1.0.0"), "a leaf has no outgoing edge")
	})

	t.Run("the root is hashed under the sentinel, and no synthetic node reaches the nodes", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/leaf@1.0.0"},
		}), "src", MerkleRootID)

		for _, n := range tree.Nodes() {
			assert.NotContains(t, n.ComponentID, "sbom:", "synthetic nodes must not reach the node table")
			assert.NotContains(t, n.ComponentID, "artifact:")
		}

		root := tree.RootNode()
		require.NotNil(t, root)
		assert.Equal(t, MerkleRootID, root.ComponentID,
			"the artifact name lives in the sboms row, not in the root hash")
	})

	t.Run("fan-out A->B, A->C shares one subtree hash across two rows", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"},
		}), "src", "my-app")

		rows := rowsFor(tree, "pkg:npm/a@1.0.0")
		require.Len(t, rows, 2, "a node with two children has two rows")
		assert.Equal(t, rows[0].SubtreeHash, rows[1].SubtreeHash, "both rows share one subtree hash")
	})

	t.Run("a subtree shared by two parents is stored once", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/shared@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/shared@1.0.0"},
		}), "src", "my-app")

		assert.Len(t, nodesFor(tree, "pkg:npm/shared@1.0.0"), 1)
	})

	t.Run("agreeing SBOMs produce identical rows, so the subtree is stored once", func(t *testing.T) {
		a := BuildMerkleTree(adjacency(map[string][]string{
			"src":                    {"pkg:golang/circl@1.6.3"},
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.1.0"},
		}), "src", MerkleRootID)
		b := BuildMerkleTree(adjacency(map[string][]string{
			"other":                  {"pkg:golang/circl@1.6.3"},
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.1.0"},
		}), "other", MerkleRootID)

		assert.Equal(t,
			edgeSet(rowsFor(a, "pkg:golang/circl@1.6.3")),
			edgeSet(rowsFor(b, "pkg:golang/circl@1.6.3")),
			"the shared subtree must be byte-identical in both SBOMs")

		assert.Equal(t, a.Root, b.Root,
			"two artifacts with the same dependencies share one root - which artifact it is lives in the sboms row")
	})

	t.Run("disagreeing SBOMs keep both edge sets", func(t *testing.T) {
		// the case the old last-write-wins edge table could not represent: a
		// rescan of one artifact used to rewrite what every other artifact saw
		a := BuildMerkleTree(adjacency(map[string][]string{
			"src":                    {"pkg:golang/circl@1.6.3"},
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.1.0"},
		}), "src", "app")
		b := BuildMerkleTree(adjacency(map[string][]string{
			"src":                    {"pkg:golang/circl@1.6.3"},
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.2.0"},
		}), "src", "app")

		circlA := rowsFor(a, "pkg:golang/circl@1.6.3")
		circlB := rowsFor(b, "pkg:golang/circl@1.6.3")
		require.Len(t, circlA, 1)
		require.Len(t, circlB, 1)
		assert.NotEqual(t, circlA[0].SubtreeHash, circlB[0].SubtreeHash,
			"disagreeing child sets must not collapse onto one hash")
	})

	t.Run("hashing is independent of child order", func(t *testing.T) {
		a := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"},
		}), "src", "my-app")
		b := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0"},
		}), "src", "my-app")

		assert.Equal(t, a.Root, b.Root)
		assert.Equal(t, edgeSet(a.Edges()), edgeSet(b.Edges()))
	})

	t.Run("a dependency cycle terminates and drops the closing edge", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/a@1.0.0"}, // back edge
		}), "src", "my-app")

		assert.NotEmpty(t, tree.Root)
		require.Len(t, nodesFor(tree, "pkg:npm/b@1.0.0"), 1)
		assert.Empty(t, rowsFor(tree, "pkg:npm/b@1.0.0"),
			"the node closing the cycle is stored as a leaf")
	})

	t.Run("an empty SBOM still yields a root hash", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{}), "src", "my-app")

		assert.NotEmpty(t, tree.Root)
		assert.Empty(t, tree.Edges(), "an empty SBOM has no edges at all")
		require.Len(t, tree.Nodes(), 1, "only the root node is stored")
	})

	t.Run("a node id that is not a purl falls back to its own id", func(t *testing.T) {
		tree := BuildMerkleTree(Adjacency{
			Children:     map[string][]string{"src": {"some-binary"}},
			ComponentIDs: map[string]string{"some-binary": ""},
		}, "src", "my-app")

		assert.Len(t, nodesFor(tree, "some-binary"), 1)
	})
}

func TestMerkleTreeRoundTrip(t *testing.T) {
	t.Run("edges survive a store and load cycle", func(t *testing.T) {
		original := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/leaf@1.0.0"},
		}), "src", "my-app")

		loaded, err := MerkleTreeFromNodesAndEdges(original.Nodes(), original.Edges(), original.Root)
		require.NoError(t, err)

		assert.Equal(t, original.Root, loaded.Root)
		assert.Equal(t, original.Len(), loaded.Len())
		assert.Equal(t, original.ComponentIDs(), loaded.ComponentIDs())
		assert.Equal(t, original.DirectDependencies(), loaded.DirectDependencies())
		assert.Equal(t, edgeSet(original.Edges()), edgeSet(loaded.Edges()))
	})

	t.Run("loading with a root that is absent from the edges is an error", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/a@1.0.0"},
		}), "src", "my-app")

		_, err := MerkleTreeFromNodesAndEdges(tree.Nodes(), tree.Edges(), uuid.New())
		require.Error(t, err)
	})

	t.Run("rebuilding the same document reproduces the same root hash", func(t *testing.T) {
		build := func() *MerkleTree {
			return BuildMerkleTree(adjacency(map[string][]string{
				"src":             {"pkg:npm/a@1.0.0"},
				"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			}), "src", "my-app")
		}

		assert.Equal(t, build().Root, build().Root,
			"an unchanged SBOM must re-ingest as a no-op")
	})
}

func TestMerkleTreeAccessors(t *testing.T) {
	tree := BuildMerkleTree(adjacency(map[string][]string{
		"src":             {"pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0"},
		"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
	}), "src", "my-app")

	t.Run("ComponentIDs excludes the artifact itself", func(t *testing.T) {
		assert.Equal(t, []string{
			"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/d@1.0.0",
		}, tree.ComponentIDs())
	})

	t.Run("DirectDependencies returns only the SBOM's own dependencies", func(t *testing.T) {
		assert.Equal(t, []string{"pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0"}, tree.DirectDependencies())
	})
}

func TestMerkleForest(t *testing.T) {
	// two origins of one artifact that disagree about what b depends on
	npm := buildTree(map[string][]string{
		merkleParseRoot:   {"pkg:npm/a@1.0.0"},
		"pkg:npm/a@1.0.0": {"pkg:npm/shared@1.0.0"},
	}, "my-app")
	golang := buildTree(map[string][]string{
		merkleParseRoot:      {"pkg:golang/x@1.0.0"},
		"pkg:golang/x@1.0.0": {"pkg:npm/shared@1.0.0"},
	}, "my-app")
	forest := MerkleForest{npm, golang}

	t.Run("components are unioned across SBOMs", func(t *testing.T) {
		assert.Equal(t, []string{
			"pkg:golang/x@1.0.0", "pkg:npm/a@1.0.0", "pkg:npm/shared@1.0.0",
		}, forest.ComponentIDs())
	})

	t.Run("a component reported by two SBOMs is flagged as shared", func(t *testing.T) {
		assert.Equal(t, []string{"pkg:npm/shared@1.0.0"}, forest.ComponentsInMultipleSBOMs())
	})

	t.Run("paths from every SBOM are reported, so neither source is lost", func(t *testing.T) {
		paths := forest.PathsToPURL("pkg:npm/shared@1.0.0", 0)

		assert.Equal(t, []string{
			"pkg:npm/a@1.0.0,pkg:npm/shared@1.0.0",
			"pkg:golang/x@1.0.0,pkg:npm/shared@1.0.0",
		}, pathStrings(paths))
	})

	t.Run("identical paths in two SBOMs are reported once", func(t *testing.T) {
		duplicate := MerkleForest{npm, npm}

		assert.Len(t, duplicate.PathsToPURL("pkg:npm/shared@1.0.0", 0), 1)
	})

	t.Run("a limit caps the total across SBOMs", func(t *testing.T) {
		assert.Len(t, forest.PathsToPURL("pkg:npm/shared@1.0.0", 1), 1)
	})

	t.Run("an empty forest yields nothing", func(t *testing.T) {
		empty := MerkleForest{}

		assert.Empty(t, empty.ComponentIDs())
		assert.Empty(t, empty.PathsToPURL("pkg:npm/anything@1.0.0", 0))
		assert.Empty(t, empty.ComponentsInMultipleSBOMs())
	})
}
