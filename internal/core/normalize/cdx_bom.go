package normalize

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

type cdxBom struct {
	bom *cdx.BOM
}

func (b *cdxBom) GetComponents() *[]cdx.Component {
	return b.bom.Components
}

func (b *cdxBom) GetDependencies() *[]cdx.Dependency {
	return b.bom.Dependencies
}

func (b *cdxBom) GetMetadata() *cdx.Metadata {
	return b.bom.Metadata
}

func FromCdxBom(bom *cdx.BOM) *cdxBom {
	components := []cdx.Component{}
	for _, c := range *bom.Components {
		component := c
		component.PackageURL = normalizePurl(component.PackageURL)
		components = append(components, component)
	}
	bom.Components = &components
	return &cdxBom{bom: bom}
}
