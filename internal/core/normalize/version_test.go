package normalize_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/stretchr/testify/assert"
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

	t.Run("valid semver with dash", func(t *testing.T) {
		semver := normalize.ConvertToSemver("1.2.3-rc1")
		assert.Equal(t, "1.2.3-rc1", semver)
	})
}
