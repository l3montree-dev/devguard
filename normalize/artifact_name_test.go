package normalize_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
)

// TestArtifactName reproduces https://github.com/l3montree-dev/devguard/issues/2579
//
// If an already-url-encoded string is stored verbatim as an artifact name
// (e.g. because a CI pipeline url-encoded the name before setting it in
// X-Artifact-Name), it can end up decoding to the same value as a
// differently-named, already-existing artifact once that name is placed in
// a URL. Actions (delete/update) then silently apply to the wrong artifact.
//
// The fix is to canonicalize (url-decode once) artifact names at creation
// time, so an already-encoded name is normalized to the same canonical form
// used everywhere else instead of being stored as a distinct, colliding
// name.
func TestArtifactName(t *testing.T) {
	t.Run("decodes an already-url-encoded name to its canonical form", func(t *testing.T) {
		assert.Equal(t, "pkg:oci/@opencode/duckdb", normalize.ArtifactName("pkg%3Aoci%2F%40opencode%2Fduckdb"))
	})

	t.Run("is idempotent - a canonical name is left untouched", func(t *testing.T) {
		assert.Equal(t, "pkg:oci/@opencode/duckdb", normalize.ArtifactName("pkg:oci/@opencode/duckdb"))
	})

	t.Run("normalizing an already-encoded name collides with its canonical form (by design)", func(t *testing.T) {
		canonical := normalize.ArtifactName("pkg:oci/@opencode/duckdb")
		fromEncodedInput := normalize.ArtifactName("pkg%3Aoci%2F%40opencode%2Fduckdb")
		assert.Equal(t, canonical, fromEncodedInput, "both must normalize to the same artifact - otherwise the two would be indistinguishable once referenced by URL")
	})

	t.Run("falls back to the original string when it is not validly encoded", func(t *testing.T) {
		assert.Equal(t, "100% not-encoded", normalize.ArtifactName("100% not-encoded"))
	})

	t.Run("empty string stays empty", func(t *testing.T) {
		assert.Equal(t, "", normalize.ArtifactName(""))
	})
}
