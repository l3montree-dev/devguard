package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pathStrings(paths []Path) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p.String())
	}
	return out
}

func TestPathsToPURL(t *testing.T) {
	t.Run("a direct dependency yields a single one element path", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/a@1.0.0"},
		}), "src", "my-app")

		paths := tree.PathsToPURL("pkg:npm/a@1.0.0", 0)

		assert.Equal(t, []string{"pkg:npm/a@1.0.0"}, pathStrings(paths),
			"the root is not part of the path")
	})

	t.Run("a transitive dependency yields the chain from the direct dependency down", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/c@1.0.0"},
		}), "src", "my-app")

		paths := tree.PathsToPURL("pkg:npm/c@1.0.0", 0)

		assert.Equal(t, []string{"pkg:npm/a@1.0.0,pkg:npm/b@1.0.0,pkg:npm/c@1.0.0"}, pathStrings(paths))
	})

	t.Run("a component reachable two ways yields both paths, shortest first", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/target@1.0.0", "pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/target@1.0.0"},
		}), "src", "my-app")

		paths := tree.PathsToPURL("pkg:npm/target@1.0.0", 0)

		require.Len(t, paths, 2)
		assert.Equal(t, "pkg:npm/target@1.0.0", paths[0].String(),
			"breadth-first, so the direct path comes first")
		assert.Equal(t, "pkg:npm/a@1.0.0,pkg:npm/b@1.0.0,pkg:npm/target@1.0.0", paths[1].String())
	})

	t.Run("a limit keeps the most direct paths", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/target@1.0.0", "pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/target@1.0.0"},
		}), "src", "my-app")

		paths := tree.PathsToPURL("pkg:npm/target@1.0.0", 1)

		assert.Equal(t, []string{"pkg:npm/target@1.0.0"}, pathStrings(paths))
	})

	t.Run("a component absent from the SBOM has no paths", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/a@1.0.0"},
		}), "src", "my-app")

		assert.Nil(t, tree.PathsToPURL("pkg:npm/absent@1.0.0", 0))
	})

	t.Run("matching a purl is case insensitive", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src": {"pkg:npm/A@1.0.0"},
		}), "src", "my-app")

		assert.Len(t, tree.PathsToPURL("pkg:npm/a@1.0.0", 0), 1)
	})

	t.Run("paths are stable across rebuilds, because vuln hashes depend on them", func(t *testing.T) {
		build := func() *MerkleTree {
			return BuildMerkleTree(adjacency(map[string][]string{
				"src":             {"pkg:npm/a@1.0.0", "pkg:npm/x@1.0.0"},
				"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
				"pkg:npm/x@1.0.0": {"pkg:npm/b@1.0.0"},
				"pkg:npm/b@1.0.0": {"pkg:npm/target@1.0.0"},
			}), "src", "my-app")
		}

		first := pathStrings(build().PathsToPURL("pkg:npm/target@1.0.0", 0))
		for range 20 {
			assert.Equal(t, first, pathStrings(build().PathsToPURL("pkg:npm/target@1.0.0", 0)))
		}
	})

	t.Run("paths survive a store and load cycle", func(t *testing.T) {
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":             {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/target@1.0.0"},
		}), "src", "my-app")

		loaded, err := MerkleTreeFromEdges(tree.Edges(), tree.Root)
		require.NoError(t, err)

		assert.Equal(t,
			pathStrings(tree.PathsToPURL("pkg:npm/target@1.0.0", 0)),
			pathStrings(loaded.PathsToPURL("pkg:npm/target@1.0.0", 0)))
	})

	t.Run("a component with two different child sets keeps its paths separate", func(t *testing.T) {
		// b appears twice: once depending on target, once as a leaf. The
		// purl-keyed graph merged these into one node; here they are distinct
		// subtrees, so only the real path to target is reported.
		tree := BuildMerkleTree(adjacency(map[string][]string{
			"src":                      {"pkg:npm/withTarget@1.0.0", "pkg:npm/without@1.0.0"},
			"pkg:npm/withTarget@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/without@1.0.0":    {"pkg:npm/bLeaf@1.0.0"},
			"pkg:npm/b@1.0.0":          {"pkg:npm/target@1.0.0"},
		}), "src", "my-app")

		paths := tree.PathsToPURL("pkg:npm/target@1.0.0", 0)

		assert.Equal(t, []string{"pkg:npm/withTarget@1.0.0,pkg:npm/b@1.0.0,pkg:npm/target@1.0.0"},
			pathStrings(paths))
	})
}
