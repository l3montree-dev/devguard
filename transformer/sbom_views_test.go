package transformer

import (
	"github.com/l3montree-dev/devguard/normalize"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToMinimalTree(t *testing.T) {
	t.Run("simple tree with components", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/lodash@4.17.21", "pkg:npm/express@4.18.2"},
		}, "my-app")

		mt := ToMinimalTree(normalize.MerkleForest{tree})

		assert.Contains(t, mt.Nodes, "pkg:npm/lodash@4.17.21")
		assert.Contains(t, mt.Nodes, "pkg:npm/express@4.18.2")
		assert.Contains(t, mt.Dependencies[""], "pkg:npm/lodash@4.17.21")
		assert.Contains(t, mt.Dependencies[""], "pkg:npm/express@4.18.2")
	})

	t.Run("tree with component dependencies", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot:   {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/c@1.0.0"},
		}, "my-app")

		mt := ToMinimalTree(normalize.MerkleForest{tree})

		assert.Contains(t, mt.Nodes, "pkg:npm/a@1.0.0")
		assert.Contains(t, mt.Nodes, "pkg:npm/b@1.0.0")
		assert.Contains(t, mt.Nodes, "pkg:npm/c@1.0.0")
		assert.Contains(t, mt.Dependencies["pkg:npm/a@1.0.0"], "pkg:npm/b@1.0.0")
		assert.Contains(t, mt.Dependencies["pkg:npm/b@1.0.0"], "pkg:npm/c@1.0.0")
		assert.Empty(t, mt.Dependencies["pkg:npm/c@1.0.0"])
	})

	t.Run("a dependency cycle in the input does not appear in the minimal tree", func(t *testing.T) {
		// A content-addressed tree cannot represent a cycle: every node is keyed
		// by its own, necessarily acyclic, subtree hash, so BuildMerkleTree drops
		// the closing edge (see "a dependency cycle terminates and drops the
		// closing edge" in merkle_tree_test.go). c's dependency back onto a is
		// therefore gone here too.
		tree := buildTree(map[string][]string{
			merkleParseRoot:   {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
			"pkg:npm/b@1.0.0": {"pkg:npm/c@1.0.0"},
			"pkg:npm/c@1.0.0": {"pkg:npm/a@1.0.0"}, // back edge
		}, "my-app")

		mt := ToMinimalTree(normalize.MerkleForest{tree})

		assert.Contains(t, mt.Nodes, "pkg:npm/a@1.0.0")
		assert.Contains(t, mt.Nodes, "pkg:npm/b@1.0.0")
		assert.Contains(t, mt.Nodes, "pkg:npm/c@1.0.0")
		assert.Contains(t, mt.Dependencies["pkg:npm/a@1.0.0"], "pkg:npm/b@1.0.0")
		assert.Contains(t, mt.Dependencies["pkg:npm/b@1.0.0"], "pkg:npm/c@1.0.0")
		assert.NotContains(t, mt.Dependencies["pkg:npm/c@1.0.0"], "pkg:npm/a@1.0.0",
			"the edge closing the cycle is dropped by design")
	})

	t.Run("the artifact itself is the empty string", func(t *testing.T) {
		tree := buildTree(map[string][]string{}, "my-app")

		mt := ToMinimalTree(normalize.MerkleForest{tree})

		assert.Contains(t, mt.Nodes, "")
		assert.Empty(t, mt.Dependencies[""])
	})

	t.Run("two SBOMs of one artifact are unioned", func(t *testing.T) {
		npm := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/a@1.0.0"},
		}, "my-app")
		golang := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:golang/x@1.0.0"},
		}, "my-app")

		mt := ToMinimalTree(normalize.MerkleForest{npm, golang})

		assert.Contains(t, mt.Dependencies[""], "pkg:npm/a@1.0.0")
		assert.Contains(t, mt.Dependencies[""], "pkg:golang/x@1.0.0")
	})
}

func TestMinimalTreeToPURL(t *testing.T) {
	forest := normalize.MerkleForest{buildTree(map[string][]string{
		merkleParseRoot:   {"pkg:npm/a@1.0.0", "pkg:npm/unrelated@1.0.0"},
		"pkg:npm/a@1.0.0": {"pkg:npm/b@1.0.0"},
		"pkg:npm/b@1.0.0": {"pkg:npm/target@1.0.0"},
	}, "my-app")}

	t.Run("keeps only the components leading to the target", func(t *testing.T) {
		mt := MinimalTreeToPURL(forest, "pkg:npm/target@1.0.0", 0)

		assert.Contains(t, mt.Nodes, "pkg:npm/target@1.0.0")
		assert.Contains(t, mt.Nodes, "pkg:npm/b@1.0.0")
		assert.Contains(t, mt.Nodes, "pkg:npm/a@1.0.0")
		assert.NotContains(t, mt.Nodes, "pkg:npm/unrelated@1.0.0")
	})

	t.Run("the ancestor chain is reported as dependency edges", func(t *testing.T) {
		mt := MinimalTreeToPURL(forest, "pkg:npm/target@1.0.0", 0)

		assert.Contains(t, mt.Dependencies["pkg:npm/b@1.0.0"], "pkg:npm/target@1.0.0")
		assert.Contains(t, mt.Dependencies["pkg:npm/a@1.0.0"], "pkg:npm/b@1.0.0")
		assert.Contains(t, mt.Dependencies[""], "pkg:npm/a@1.0.0")
	})

	t.Run("maxDepth counts hops back from the target", func(t *testing.T) {
		mt := MinimalTreeToPURL(forest, "pkg:npm/target@1.0.0", 1)

		assert.Contains(t, mt.Nodes, "pkg:npm/b@1.0.0")
		assert.NotContains(t, mt.Nodes, "pkg:npm/a@1.0.0",
			"a is two hops away, so a depth of one stops before it")
	})

	t.Run("a component absent from the forest yields nothing", func(t *testing.T) {
		mt := MinimalTreeToPURL(forest, "pkg:npm/absent@1.0.0", 0)

		assert.Empty(t, mt.Nodes)
		assert.Empty(t, mt.Dependencies)
	})
}
