package normalize

import cdx "github.com/CycloneDX/cyclonedx-go"

type SBOM interface {
	GetComponents() *[]cdx.Component
	GetDependencies() *[]cdx.Dependency
	GetMetadata() *cdx.Metadata
	GetCdxBom() *cdx.BOM
}
