package commands

import (
	"errors"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func newUpstreamTestBOM() *cyclonedx.BOM {
	return &cyclonedx.BOM{
		Metadata:   &cyclonedx.Metadata{Component: &cyclonedx.Component{BOMRef: "root"}},
		Components: &[]cyclonedx.Component{},
		Dependencies: &[]cyclonedx.Dependency{
			{Ref: "root", Dependencies: &[]string{}},
		},
	}
}

func TestAddSupplementaryUpstreamPURLManually(t *testing.T) {
	origPURL, origVCS := config.RuntimeBaseConfig.UpstreamPURL, config.RuntimeBaseConfig.UpstreamVCS
	t.Cleanup(func() {
		config.RuntimeBaseConfig.UpstreamPURL, config.RuntimeBaseConfig.UpstreamVCS = origPURL, origVCS
	})

	t.Run("no-op when no upstream purls are configured", func(t *testing.T) {
		config.RuntimeBaseConfig.UpstreamPURL, config.RuntimeBaseConfig.UpstreamVCS = nil, nil
		bom := newUpstreamTestBOM()
		assert.NoError(t, addSupplementaryUpstreamPURLManually(bom, mocks.NewOpenSourceInsightService(t)))
		assert.Empty(t, *bom.Components)
	})

	t.Run("adds a component per purl and links each to the root", func(t *testing.T) {
		config.RuntimeBaseConfig.UpstreamPURL = []string{"pkg:golang/example.org/a@v1.0.0", "pkg:npm/b@2.0.0"}
		config.RuntimeBaseConfig.UpstreamVCS = nil
		bom := newUpstreamTestBOM()
		svc := mocks.NewOpenSourceInsightService(t)
		svc.EXPECT().GetVersion(mock.Anything, mock.Anything).Return(dtos.OpenSourceInsightsVersionResponse{}, nil).Times(2)
		assert.NoError(t, addSupplementaryUpstreamPURLManually(bom, svc))

		assert.Len(t, *bom.Components, 2)
		assert.Equal(t, "pkg:golang/example.org/a@v1.0.0", (*bom.Components)[0].PackageURL)
		assert.Equal(t, "v1.0.0", (*bom.Components)[0].Version)
		assert.Equal(t, cyclonedx.ComponentTypeApplication, (*bom.Components)[0].Type)
		assert.Nil(t, (*bom.Components)[0].Pedigree)
		assert.Equal(t, []string{"pkg:golang/example.org/a@v1.0.0", "pkg:npm/b@2.0.0"}, *(*bom.Dependencies)[0].Dependencies)
	})

	t.Run("maps VCS values to purls by index", func(t *testing.T) {
		config.RuntimeBaseConfig.UpstreamPURL = []string{"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"}
		config.RuntimeBaseConfig.UpstreamVCS = []string{"git:github.com/org/a.git@main"}
		bom := newUpstreamTestBOM()
		svc := mocks.NewOpenSourceInsightService(t)
		svc.EXPECT().GetVersion(mock.Anything, mock.Anything).Return(dtos.OpenSourceInsightsVersionResponse{}, nil).Times(2)
		assert.NoError(t, addSupplementaryUpstreamPURLManually(bom, svc))

		assert.Len(t, *bom.Components, 2)
		first := (*bom.Components)[0]
		assert.NotNil(t, first.Pedigree)
		refs := *(*first.Pedigree.Ancestors)[0].ExternalReferences
		assert.Equal(t, "git:github.com/org/a.git@main", refs[0].URL)
		assert.Nil(t, (*bom.Components)[1].Pedigree)
	})

	t.Run("errors on a purl without a version", func(t *testing.T) {
		config.RuntimeBaseConfig.UpstreamPURL = []string{"pkg:npm/a"}
		config.RuntimeBaseConfig.UpstreamVCS = nil
		assert.Error(t, addSupplementaryUpstreamPURLManually(newUpstreamTestBOM(), mocks.NewOpenSourceInsightService(t)))
	})

	t.Run("errors on an invalid purl", func(t *testing.T) {
		config.RuntimeBaseConfig.UpstreamPURL = []string{"not-a-purl"}
		config.RuntimeBaseConfig.UpstreamVCS = nil
		assert.Error(t, addSupplementaryUpstreamPURLManually(newUpstreamTestBOM(), mocks.NewOpenSourceInsightService(t)))
	})

	t.Run("still adds the component when the lookup fails", func(t *testing.T) {
		config.RuntimeBaseConfig.UpstreamPURL = []string{"pkg:npm/does-not-exist@1.0.0"}
		config.RuntimeBaseConfig.UpstreamVCS = nil
		bom := newUpstreamTestBOM()
		svc := mocks.NewOpenSourceInsightService(t)
		svc.EXPECT().GetVersion(mock.Anything, mock.Anything).Return(dtos.OpenSourceInsightsVersionResponse{}, errors.New("404 Not Found")).Once()
		assert.NoError(t, addSupplementaryUpstreamPURLManually(bom, svc))

		assert.Len(t, *bom.Components, 1)
		assert.Equal(t, "pkg:npm/does-not-exist@1.0.0", (*bom.Components)[0].PackageURL)
	})
}
