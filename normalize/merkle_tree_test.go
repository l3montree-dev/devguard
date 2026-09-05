package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adjacency builds an Adjacency where every node's component identity is its
// own id, which is how a purl-identified document parses.
func adjacency(children map[string][]string) Adjacency {
	return Adjacency{Children: children, ComponentIDs: map[string]string{}}
}

func edgeKey(e MerkleEdge) [3]string {
	child := "NULL"
	if e.DirectDependencySubtreeHash != nil {
		child = *e.DirectDependencySubtreeHash
	}
	return [3]string{e.SubtreeHash, e.ComponentID, child}
}

func edgeSet(edges []MerkleEdge) map[[3]string]struct{} {
	set := make(map[[3]string]struct{}, len(edges))
	for _, e := range edges {
		set[edgeKey(e)] = struct{}{}
	}
	return set
}

func rowsFor(edges []MerkleEdge, componentID string) []MerkleEdge {
	var rows []MerkleEdge
	for _, e := range edges {
		if e.ComponentID == componentID {
			rows = append(rows, e)
		}
	}
	return rows
}

func TestBuildMerkleTree(t *testing.T) {
	t.Run("a leaf gets a row with a nil child, so its component id stays resolvable", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/leaf@1.0.0"},
		}), "src", "my-artifact")

		rows := rowsFor(tree.Edges(), "pkg:npm/leaf@1.0.0")
		require.Len(t, rows, 1, "a leaf must have a row of its own")
		assert.Nil(t, rows[0].DirectDependencySubtreeHash)
	})

	t.Run("the root is hashed under the artifact identity, never a sentinel", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/leaf@1.0.0"},
		}), "src", "my-app")

		for _, e := range tree.Edges() {
			assert.NotEqual(t, "ROOT", e.ComponentID, "the ROOT sentinel is replaced by the sboms pivot table")
			assert.NotContains(t, e.ComponentID, "sbom:", "synthetic nodes must not reach the edge table")
			assert.NotContains(t, e.ComponentID, "artifact:")
		}

		root := tree.RootNode()
		require.NotNil(t, root)
		assert.Equal(t, "my-app", root.ComponentID)
	})

	t.Run("fan-out A->B, A->C shares one subtree hash across two rows", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"},
		}), "src", "my-app")

		rows := rowsFor(tree.Edges(), "pkg:npm/a@1.0.0")
		require.Len(t, rows, 2, "a node with two children has two rows")
		assert.Equal(t, rows[0].SubtreeHash, rows[1].SubtreeHash, "both rows share one subtree hash")
	})

	t.Run("a subtree shared by two parents is stored once", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/shared@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/shared@1.0.0"},
		}), "src", "my-app")

		assert.Len(t, rowsFor(tree.Edges(), "pkg:npm/shared@1.0.0"), 1)
	})

	t.Run("agreeing SBOMs produce identical rows, so the subtree is stored once", func(t *testing.T) {
		a := BuildMerkleTree(adjacency(map[string][]string{
			"src":                    {"pkg:golang/circl@1.6.3"},
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.1.0"},
		}), "src", "app-one")
		b := BuildMerkleTree(adjacency(map[string][]string{
			"other":                  {"pkg:golang/circl@1.6.3"},
			"pkg:golang/circl@1.6.3": {"pkg:golang/sys@0.1.0"},
		}), "other", "app-two")

		assert.Equal(t,
			edgeSet(rowsFor(a.Edges(), "pkg:golang/circl@1.6.3")),
			edgeSet(rowsFor(b.Edges(), "pkg:golang/circl@1.6.3")),
			"the shared subtree must be byte-identical in both SBOMs")

		assert.NotEqual(t, a.Root, b.Root, "different artifacts are different SBOMs")
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

		circlA := rowsFor(a.Edges(), "pkg:golang/circl@1.6.3")
		circlB := rowsFor(b.Edges(), "pkg:golang/circl@1.6.3")
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
		rows := rowsFor(tree.Edges(), "pkg:npm/b@1.0.0")
		require.Len(t, rows, 1)
		assert.Nil(t, rows[0].DirectDependencySubtreeHash,
			"the node closing the cycle is stored as a leaf")
	})

	t.Run("an empty SBOM still yields a root hash", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{}), "src", "my-app")

		assert.NotEmpty(t, tree.Root)
		edges := tree.Edges()
		require.Len(t, edges, 1)
		assert.Nil(t, edges[0].DirectDependencySubtreeHash)
	})

	t.Run("a node id that is not a purl falls back to its own id", func(t *testing.T) {
		tree := BuildMerkleTree(Adjacency{
			Children:     map[string][]string{"src": {"some-binary"}},
			ComponentIDs: map[string]string{"some-binary": ""},
		}, "src", "my-app")

		assert.Len(t, rowsFor(tree.Edges(), "some-binary"), 1)
	})
}

func TestMerkleTreeRoundTrip(t *testing.T) {
	t.Run("edges survive a store and load cycle", func(t *testing.T) {
		original := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0", "pkg:npm/d@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/leaf@1.0.0"},
		}), "src", "my-app")

		loaded, err := MerkleTreeFromEdges(original.Edges(), original.Root)
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

		_, err := MerkleTreeFromEdges(tree.Edges(), "not-a-stored-hash")
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
