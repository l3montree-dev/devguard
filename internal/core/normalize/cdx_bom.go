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

// if the second parameter is set to true, the component type will be converted to the correct type
// THIS SHOULD ONLY be done, if the component type wasnt set by us.
// if the component type was set by us, we shouldnt change it
func FromCdxBom(bom *cdx.BOM, convertComponentType bool) *cdxBom {
	components := []cdx.Component{}
	for _, c := range *bom.Components {
		component := c
		purl, componentType := normalizePurl(component.PackageURL)
		if convertComponentType {
			component.Type = componentType
		}
		component.PackageURL = purl
		components = append(components, component)
	}
	bom.Components = &components
	return &cdxBom{bom: bom}
}
