package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImagePairTagFor(t *testing.T) {
	t.Run("returns the plain ref without upstream version", func(t *testing.T) {
		assert.Equal(t, "v1.20.1", imagePair{}.tagFor("v1.20.1"))
	})

	t.Run("prefixes the ref with the upstream version", func(t *testing.T) {
		assert.Equal(t, "v26.2.0-v1.20.1", imagePair{upstreamVersion: "v26.2.0"}.tagFor("v1.20.1"))
	})

	t.Run("reverses stripUpstreamVersion", func(t *testing.T) {
		pair := imagePair{upstreamVersion: "v26.2.0"}
		refs := stripUpstreamVersion([]string{"v26.2.0-main", "v26.2.0-v1.20.1", "v26.2.0"}, pair.upstreamVersion)
		assert.Equal(t, []string{"main", "v1.20.1"}, refs)
		for _, ref := range refs {
			assert.Equal(t, "v26.2.0-"+ref, pair.tagFor(ref))
		}
	})
}
