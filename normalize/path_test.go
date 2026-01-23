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

func TestPathToStringSliceComponentOnly(t *testing.T) {
	t.Run("filters out ROOT node", func(t *testing.T) {
		path := normalize.Path{"ROOT", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[0])
	})

	t.Run("filters out root node (lowercase)", func(t *testing.T) {
		path := normalize.Path{"root", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[0])
	})

	t.Run("filters out artifact nodes", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[0])
	})

	t.Run("filters out sbom info source nodes", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "sbom:package-lock.json", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[0])
	})

	t.Run("filters out vex info source nodes", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "vex:security-report.json", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[0])
	})

	t.Run("filters out csaf info source nodes", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "csaf:advisory.json", "pkg:npm/lodash@4.17.21"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[0])
	})

	t.Run("keeps only component PURLs in deep path", func(t *testing.T) {
		path := normalize.Path{
			"ROOT",
			"artifact:my-app",
			"sbom:package-lock.json",
			"pkg:npm/express@4.18.0",
			"pkg:npm/body-parser@1.20.0",
			"pkg:npm/lodash@4.17.21",
		}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 3)
		assert.Equal(t, "pkg:npm/express@4.18.0", result[0])
		assert.Equal(t, "pkg:npm/body-parser@1.20.0", result[1])
		assert.Equal(t, "pkg:npm/lodash@4.17.21", result[2])
	})

	t.Run("returns empty slice when path only contains fake nodes", func(t *testing.T) {
		path := normalize.Path{"ROOT", "artifact:my-app", "sbom:package-lock.json"}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 0)
	})

	t.Run("returns empty slice for empty path", func(t *testing.T) {
		path := normalize.Path{}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 0)
	})

	t.Run("handles mixed golang and npm purls", func(t *testing.T) {
		path := normalize.Path{
			"ROOT",
			"artifact:app",
			"sbom:go.mod",
			"pkg:golang/github.com/gin-gonic/gin@1.9.0",
			"pkg:golang/golang.org/x/net@0.10.0",
		}

		result := path.ToStringSliceComponentOnly()

		assert.Len(t, result, 2)
		assert.Equal(t, "pkg:golang/github.com/gin-gonic/gin@1.9.0", result[0])
		assert.Equal(t, "pkg:golang/golang.org/x/net@0.10.0", result[1])
	})
}

func TestPathIntegration(t *testing.T) {
	t.Run("full path lifecycle", func(t *testing.T) {
		// Create a realistic path as it would be saved in the database
		fullPath := normalize.Path{
			"ROOT",
			"artifact:web-app",
			"sbom:package-lock.json",
			"pkg:npm/next@14.2.13",
			"pkg:npm/react@18.2.0",
			"pkg:npm/scheduler@0.23.0",
		}

		// Get all nodes
		allNodes := fullPath.ToStringSlice()
		assert.Len(t, allNodes, 6)
		assert.Contains(t, allNodes, "ROOT")
		assert.Contains(t, allNodes, "artifact:web-app")

		// Get component-only nodes for hash calculation or depth
		componentNodes := fullPath.ToStringSliceComponentOnly()
		assert.Len(t, componentNodes, 3)
		assert.Equal(t, "pkg:npm/next@14.2.13", componentNodes[0])
		assert.Equal(t, "pkg:npm/react@18.2.0", componentNodes[1])
		assert.Equal(t, "pkg:npm/scheduler@0.23.0", componentNodes[2])

		// Verify fake nodes are filtered out
		for _, node := range componentNodes {
			assert.NotEqual(t, "ROOT", node)
			assert.False(t, len(node) > 9 && node[:9] == "artifact:")
			assert.False(t, len(node) > 5 && node[:5] == "sbom:")
		}
	})
}
