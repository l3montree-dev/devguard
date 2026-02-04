package normalize_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
)

func TestPathToStringSlice(t *testing.T) {
	t.Run("returns all nodes including fake nodes", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "sbom:package-lock.json", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSlice()

		assert.Len(t, result, 4)
		assert.Equal(t, "ROOT", result[0])
		assert.Equal(t, "artifact:my-app", result[1])
		assert.Equal(t, "sbom:package-lock.json", result[2])
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[3])
	})

	t.Run("returns empty slice for empty path", func(t *testing.T) {
		path := normalize.Path{}

		result := path.ToStringSlice()

		assert.Len(t, result, 0)
	})

	t.Run("returns single element path", func(t *testing.T) {
		path := normalize.Path{"pkg:npm/express@4.18.0"}

		result := path.ToStringSlice()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/express@4.18.0", result[0])
	})
}

func TestPathString(t *testing.T) {
	t.Run("converts path to comma-separated string", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "pkg:npm/lodash@4.17.21"}

		result := path.String()

		assert.Equal(t, "ROOT,artifact:my-app,pkg:npm/lodash@4.17.21", result)
	})

	t.Run("returns empty string for empty path", func(t *testing.T) {
		path := normalize.Path{}

		result := path.String()

		assert.Equal(t, "", result)
	})

	t.Run("handles single element path", func(t *testing.T) {
		path := normalize.Path{"pkg:npm/express@4.18.0"}

		result := path.String()

		assert.Equal(t, "pkg:npm/express@4.18.0", result)
	})
}
