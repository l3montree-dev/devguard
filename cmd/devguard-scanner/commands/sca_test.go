package commands

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestHasVersionedDescendant(t *testing.T) {
	t.Run("false for a leaf ref with no children", func(t *testing.T) {
		children := dependencyChildrenByRef(nil)
		assert.False(t, hasVersionedDescendant("go.mod", children, map[string]bool{}))
	})

	t.Run("true when a direct child is a versioned purl", func(t *testing.T) {
		deps := []cyclonedx.Dependency{
			{Ref: "go.mod", Dependencies: &[]string{"pkg:golang/example.org/mod@v1.0.0"}},
		}
		children := dependencyChildrenByRef(&deps)
		assert.True(t, hasVersionedDescendant("go.mod", children, map[string]bool{}))
	})

	t.Run("true when the real deps sit two levels down behind an unversioned module ref", func(t *testing.T) {
		deps := []cyclonedx.Dependency{
			{Ref: "go.mod", Dependencies: &[]string{"pkg:golang/example.org/mod"}},
			{Ref: "pkg:golang/example.org/mod", Dependencies: &[]string{"pkg:golang/example.org/dep@v1.0.0"}},
		}
		children := dependencyChildrenByRef(&deps)
		assert.True(t, hasVersionedDescendant("go.mod", children, map[string]bool{}))
	})

	t.Run("false when every descendant is unversioned", func(t *testing.T) {
		deps := []cyclonedx.Dependency{
			{Ref: "go.mod", Dependencies: &[]string{"pkg:golang/example.org/mod"}},
			{Ref: "pkg:golang/example.org/mod", Dependencies: &[]string{}},
		}
		children := dependencyChildrenByRef(&deps)
		assert.False(t, hasVersionedDescendant("go.mod", children, map[string]bool{}))
	})

	t.Run("does not infinite-loop on a dependency cycle", func(t *testing.T) {
		deps := []cyclonedx.Dependency{
			{Ref: "a", Dependencies: &[]string{"b"}},
			{Ref: "b", Dependencies: &[]string{"a"}},
		}
		children := dependencyChildrenByRef(&deps)
		assert.False(t, hasVersionedDescendant("a", children, map[string]bool{}))
	})
}
