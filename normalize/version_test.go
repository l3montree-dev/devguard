package normalize_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/semver"
)

func TestConvertToSemver(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		semver := normalize.ConvertToSemver("")
		assert.Equal(t, "", semver)
	})

	t.Run("valid semver", func(t *testing.T) {
		semver := normalize.ConvertToSemver("1.2.3")
		assert.Equal(t, "1.2.3", semver)
	})

	t.Run("valid semver with pre-release", func(t *testing.T) {
		smallSemver := normalize.ConvertToSemver("1.2.3-rc1")
		biggerSemver := normalize.ConvertToSemver("1.2.3-rc2")
		assert.True(t, semver.Compare("v"+smallSemver, "v"+biggerSemver) < 0)
	})

	t.Run("valid semver with build metadata", func(t *testing.T) {
		smallSemver := normalize.ConvertToSemver("1.2.3+build1")
		biggerSemver := normalize.ConvertToSemver("1.2.4")
		assert.True(t, semver.Compare("v"+smallSemver, "v"+biggerSemver) < 0)
	})

	// pre-release should be smaller than release
	t.Run("pre-release should be smaller than release", func(t *testing.T) {
		s := normalize.ConvertToSemver("1.2.3-rc1")
		assert.True(t, semver.Compare("v1.2.3", "v"+s) > 0)
	})
}
