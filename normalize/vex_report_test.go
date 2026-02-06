package normalize

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVexReport(t *testing.T) {
	t.Run("valid VEX report", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15, // 1.5
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "pkg:npm/my-app@1.0.0",
					Name:       "my-app",
					PackageURL: "pkg:npm/my-app@1.0.0",
				},
			},
		}

		report, err := NewVexReport(bom, "vex-source")
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, bom, report.Report)
		assert.Equal(t, "vex-source", report.Source)
	})

	t.Run("missing metadata", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
		}

		report, err := NewVexReport(bom, "vex-source")
		require.Error(t, err)
		assert.Nil(t, report)
		assert.Equal(t, "invalid VEX report: missing metadata.component", err.Error())
	})

	t.Run("missing metadata component", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
			Metadata: &cdx.Metadata{
				// Component is nil
			},
		}

		report, err := NewVexReport(bom, "vex-source")
		require.Error(t, err)
		assert.Nil(t, report)
		assert.Equal(t, "invalid VEX report: missing metadata.component", err.Error())
	})

	t.Run("missing PackageURL on component", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "pkg:npm/my-app@1.0.0",
					Name:   "my-app",
					// PackageURL is empty
				},
			},
		}

		report, err := NewVexReport(bom, "vex-source")
		require.Error(t, err)
		assert.Nil(t, report)
		assert.Equal(t, "invalid VEX report: root component must have a PackageURL", err.Error())
	})

	t.Run("component with PackageURL and BOMRef", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "my-component-id",
					PackageURL: "pkg:maven/org.example/my-app@2.0.0",
				},
			},
		}

		report, err := NewVexReport(bom, "vex-source-2")
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, "vex-source-2", report.Source)
	})
}

func TestGetRootPurl(t *testing.T) {
	t.Run("valid root PURL", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "pkg:npm/my-app@1.0.0",
					PackageURL: "pkg:npm/my-app@1.0.0",
				},
			},
		}

		report, err := NewVexReport(bom, "vex-source")
		require.NoError(t, err)

		purl, err := report.GetRootPurl()
		require.NoError(t, err)
		assert.Equal(t, "npm", purl.Type)
		assert.Equal(t, "my-app", purl.Name)
		assert.Equal(t, "1.0.0", purl.Version)
	})

	t.Run("no root component", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
		}

		report, _ := NewVexReport(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "valid",
					PackageURL: "pkg:npm/test@1.0.0",
				},
			},
		}, "source")

		report.Report = bom
		purl, err := report.GetRootPurl()
		require.Error(t, err)
		assert.Empty(t, purl.Type)
	})

	t.Run("invalid PURL format", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: 15,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "id",
					PackageURL: "not-a-valid-purl",
				},
			},
		}

		report, _ := NewVexReport(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "valid",
					PackageURL: "pkg:npm/test@1.0.0",
				},
			},
		}, "source")

		report.Report = bom
		purl, err := report.GetRootPurl()
		require.Error(t, err)
		assert.Empty(t, purl.Type)
	})
}
