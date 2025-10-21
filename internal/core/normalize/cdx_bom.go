package normalize

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
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

func CdxBom(bom *cdx.BOM) *cdxBom {
	return &cdxBom{bom: bom}
}

type BomWithOrigin struct {
	cyclonedx.BOM
	Origin string
}

// if the second parameter is set to true, the component type will be converted to the correct type
// THIS SHOULD ONLY be done, if the component type wasnt set by us.
// if the component type was set by us, we shouldnt change it
func FromCdxBom(bom *cdx.BOM, artifactName, origin string, convertComponentType bool) *cdxBom {
	components := []cdx.Component{}

	for _, c := range *bom.Components {
		component := c
		// check if version key exists - if not, its not a valid purl
		if component.Version == "" {
			continue
		}

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

	componentsMap := make(map[string]cdx.Component)
	for _, comp := range components {
		componentsMap[comp.BOMRef] = comp
	}

	// we removed everything which is not a valid purl from the components slice
	// we need to make sure that we change the dependencies as well
	// Root --> A (invalid purl) --> B (invalid purl) --> C (valid purl)
	// should become
	// Root --> C
	withoutIncomingEdges := []cdx.Dependency{}
	if bom.Dependencies != nil {
		for _, doIncomingEdgesExists := range *bom.Dependencies {
			// if this is not part of components, we skip it
			_, exists := componentsMap[doIncomingEdgesExists.Ref]
			if !exists {
				continue
			}
			// we can identify components without incoming edges, if NO component depends on them - therefore we need to check all dependencies
			hasIncomingEdges := false
			for _, checkIfPointsToIncomingEdgesExist := range *bom.Dependencies {
				if checkIfPointsToIncomingEdgesExist.Ref == doIncomingEdgesExists.Ref {
					// check is NOT the dependency we are checking if
					continue
				}

				// check if part of the components slice - if not, we skip it as well
				if _, ok := componentsMap[checkIfPointsToIncomingEdgesExist.Ref]; !ok {
					// we just removed this from the component slice
					// therefore we can skip it
					continue
				}

				if checkIfPointsToIncomingEdgesExist.Dependencies != nil {
					for _, dep := range *checkIfPointsToIncomingEdgesExist.Dependencies {
						if dep == doIncomingEdgesExists.Ref {
							hasIncomingEdges = true
							break
						}
					}
				}
			}
			if !hasIncomingEdges {
				withoutIncomingEdges = append(withoutIncomingEdges, doIncomingEdgesExists)
			}
		}
	}
	// create an artificial ROOT component which points to origin
	// which then points to all components which have no incoming edges
	artificialRoot := cdx.Dependency{
		Ref:          artifactName,
		Dependencies: &[]string{origin},
	}

	withoutIncomingEdgesRefs := []string{}
	for _, e := range withoutIncomingEdges {
		withoutIncomingEdgesRefs = append(withoutIncomingEdgesRefs, e.Ref)
	}

	originDependency := cdx.Dependency{
		Ref:          origin,
		Dependencies: &withoutIncomingEdgesRefs,
	}

	dependencies := []cdx.Dependency{}
	for _, dependency := range *bom.Dependencies {
		// check if exists in components map
		_, exists := componentsMap[dependency.Ref]
		if !exists {
			continue
		}
		dependencies = append(dependencies, dependency)
	}

	// last but not least change the metadata to artificial root
	if bom.Metadata != nil {
		bom.Metadata.Component = &cdx.Component{
			BOMRef: artifactName,
			Name:   artifactName,
			Type:   cdx.ComponentTypeApplication,
		}
	}

	// and add both to the components slice
	components = append(components, cdx.Component{
		BOMRef: artifactName,
		Name:   artifactName,
		Type:   cdx.ComponentTypeApplication,
	}, cdx.Component{
		BOMRef: origin,
		Name:   origin,
		Type:   cdx.ComponentTypeApplication,
	})

	dependencies = append(dependencies, artificialRoot, originDependency)
	bom.Dependencies = &dependencies
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
	vulnMap := make(map[string]cdx.Vulnerability)

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

		if bom.Vulnerabilities != nil {
			for _, v := range *bom.Vulnerabilities {
				vulnMap[v.ID] = v
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

	vulns := []cdx.Vulnerability{}
	for _, v := range vulnMap {
		vulns = append(vulns, v)
	}
	merged.Vulnerabilities = &vulns

	return merged
}
