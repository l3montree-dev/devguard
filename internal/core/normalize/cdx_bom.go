package normalize

import (
	"strings"

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

func (b *cdxBom) GetCdxBom() *cdx.BOM {
	return b.bom
}

// if the second parameter is set to true, the component type will be converted to the correct type
// THIS SHOULD ONLY be done, if the component type wasnt set by us.
// if the component type was set by us, we shouldnt change it
func FromCdxBom(bom *cdx.BOM, convertComponentType bool) *cdxBom {
	components := []cdx.Component{}
	for _, c := range *bom.Components {
		component := c

		// check if the component is a library
		// we can detect that, if the component has a "properties" object - as long as we are using trivy for sbom generation
		if component.Properties != nil {
			// we currently have no idea, why trivy calls it src name and src version
			// we just stick with it.
			srcName := ""
			srcVersion := ""

			// will be exactly the string we need to replace inside the purl
			// please do not ask me why
			pkgID := ""
			for _, property := range *component.Properties {
				if property.Name == "aquasecurity:trivy:SrcName" {
					// never expand to whole linux - this might happen - not sure why
					if property.Value == "linux" {
						break
					}

					srcName = property.Value
				} else if property.Name == "aquasecurity:trivy:SrcVersion" {
					srcVersion = property.Value
				} else if property.Name == "aquasecurity:trivy:PkgID" {
					pkgID = property.Value
				}
			}

			// if both are defined - we can replace the package url with the new name and version
			if srcName != "" && srcVersion != "" && pkgID != "" {
				component.PackageURL = strings.ReplaceAll(component.PackageURL, pkgID, srcName+"@"+srcVersion)
			}
		}

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

func MergeCdxBoms(metadata *cdx.Metadata, boms ...*cdx.BOM) *cdx.BOM {
	merged := &cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		BOMFormat:    "CycloneDX",
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      1,
		Components:   &[]cdx.Component{},
		Dependencies: &[]cdx.Dependency{},
		Metadata:     metadata,
	}

	componentMap := make(map[string]cdx.Component)
	dependencyMap := make(map[string]cdx.Dependency)

	for _, bom := range boms {
		if bom == nil {
			continue
		}

		if bom.Components != nil {
			for _, comp := range *bom.Components {
				componentMap[comp.PackageURL] = comp
			}
		}

		if bom.Dependencies != nil {
			for _, dep := range *bom.Dependencies {
				dependencyMap[dep.Ref] = dep
			}
		}

		if bom.Metadata != nil && merged.Metadata == nil {
			merged.Metadata = bom.Metadata
		}
	}

	components := []cdx.Component{}
	for _, comp := range componentMap {
		components = append(components, comp)
	}
	merged.Components = &components

	dependencies := []cdx.Dependency{}
	for _, dep := range dependencyMap {
		dependencies = append(dependencies, dep)
	}
	merged.Dependencies = &dependencies

	return merged
}
