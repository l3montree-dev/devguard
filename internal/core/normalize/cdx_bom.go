package normalize

import (
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type cdxBom struct {
	bom    *cdx.BOM
	origin string
}

func (b *cdxBom) GetComponents() *[]cdx.Component {
	return b.bom.Components
}

func (b *cdxBom) GetOrigin() string {
	return b.origin
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

func (b *cdxBom) GetVulnerabilities() *[]cdx.Vulnerability {
	return b.bom.Vulnerabilities
}

type cdxDependency struct {
	cdx.Dependency
}

func (d cdxDependency) GetRef() string {
	return d.Ref
}

func (d cdxDependency) GetDeps() []string {
	return *d.Dependencies
}

func cdxDependencies(deps []cdx.Dependency) []cdxDependency {
	result := make([]cdxDependency, 0, len(deps))
	for _, d := range deps {
		result = append(result, cdxDependency{d})
	}
	return result
}

func CdxBom(bom *cdx.BOM) *cdxBom {
	// only remove dependencies and components which are not possible to visit from root
	tree := buildDependencyTree(cdxDependencies(*bom.Dependencies), bom.Metadata.Component.BOMRef)
	_, unvisitable := tree.Visitable()
	// remove from components and dependencies all unvisitable ones
	filteredComponents := make([]cdx.Component, 0)
	for _, comp := range *bom.Components {
		if slices.Contains(unvisitable, comp.BOMRef) {
			continue
		}
		filteredComponents = append(filteredComponents, comp)
	}
	bom.Components = &filteredComponents

	filteredDependencies := make([]cdx.Dependency, 0)
	for _, dep := range *bom.Dependencies {
		if slices.Contains(unvisitable, dep.Ref) {
			continue
		}

		// check for the deps
		newDeps := make([]string, 0)
		for _, d := range *dep.Dependencies {
			if !slices.Contains(unvisitable, d) {
				newDeps = append(newDeps, d)
			}
		}
		dep.Dependencies = &newDeps
		filteredDependencies = append(filteredDependencies, dep)
	}
	bom.Dependencies = &filteredDependencies

	return &cdxBom{bom: bom}
}

func removeUnvisitable(bom *cdx.BOM) *cdx.BOM {
	// only remove dependencies and components which are not possible to visit from root
	tree := buildDependencyTree(cdxDependencies(*bom.Dependencies), bom.Metadata.Component.BOMRef)
	_, unvisitable := tree.Visitable()
	// remove from components and dependencies all unvisitable ones
	filteredComponents := make([]cdx.Component, 0)
	for _, comp := range *bom.Components {
		if slices.Contains(unvisitable, comp.BOMRef) {
			continue
		}
		filteredComponents = append(filteredComponents, comp)
	}
	bom.Components = &filteredComponents

	filteredDependencies := make([]cdx.Dependency, 0)
	for _, dep := range *bom.Dependencies {
		if slices.Contains(unvisitable, dep.Ref) {
			continue
		}

		// check for the deps
		newDeps := make([]string, 0)
		for _, d := range *dep.Dependencies {
			if !slices.Contains(unvisitable, d) {
				newDeps = append(newDeps, d)
			}
		}
		dep.Dependencies = &newDeps
		filteredDependencies = append(filteredDependencies, dep)
	}
	bom.Dependencies = &filteredDependencies
	return bom
}

func (b cdxBom) Eject() *cdx.BOM {
	// copy bom
	bom := b.bom

	// remove all dependencies and rewrite those to SKIP invalid purls
	dependencies := []cdx.Dependency{}
	if bom.Dependencies != nil {
		for _, dependency := range *bom.Dependencies {
			d := getShortCircuitDependencies(dependency.Ref, *bom.Dependencies)
			dependencies = append(dependencies, cdx.Dependency{
				Ref:          dependency.Ref,
				Dependencies: &d,
			})
		}
	}
	bom.Dependencies = &dependencies

	bom = removeUnvisitable(bom)

	return bom
}

func replaceTrivyProperties(components []cdx.Component) []cdx.Component {
	updatedCompoents := make([]cdx.Component, 0, len(components))
	for _, component := range components {
		// check if the component is a library
		// we can detect that, if the component has a "properties" object - as long as we are using trivy for sbom generation
		if component.Properties != nil {
			// we currently have no idea, why trivy calls it src name and src version
			// we just stick with it.
			srcName := ""
			srcVersion := ""

			// will be exactly the string we need to replace inside the purl
			// src version differs in debian cases for some packages like "libc6" and openssl
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
		updatedCompoents = append(updatedCompoents, component)
	}
	return updatedCompoents
}

func normalizePurls(components []cdx.Component) []cdx.Component {
	normalizedComponents := make([]cdx.Component, 0, len(components))
	for _, component := range components {
		purl := normalizePurl(component.PackageURL)
		component.PackageURL = purl
		normalizedComponents = append(normalizedComponents, component)
	}
	return normalizedComponents
}

func flat(deps [][]string) []string {
	result := []string{}
	for _, depList := range deps {
		result = append(result, depList...)
	}
	return result
}

func getShortCircuitDependencies(ref string, allDeps []cdx.Dependency) []string {
	// Build a map once instead of linear search each time
	depMap := make(map[string]*cdx.Dependency)
	for i := range allDeps {
		depMap[allDeps[i].Ref] = &allDeps[i]
	}
	return resolveValidPurls(ref, depMap)
}

func resolveValidPurls(ref string, depMap map[string]*cdx.Dependency) []string {
	dep, ok := depMap[ref]
	if !ok || dep.Dependencies == nil {
		return []string{}
	}

	var result []string
	for _, subRef := range *dep.Dependencies {
		if strings.HasPrefix(subRef, "pkg:") {
			result = append(result, subRef)
		} else {
			result = append(result, resolveValidPurls(subRef, depMap)...)
		}
	}
	return result
}

// if the second parameter is set to true, the component type will be converted to the correct type
// THIS SHOULD ONLY be done, if the component type wasnt set by us.
// if the component type was set by us, we shouldnt change it
func FromCdxBom(bom *cdx.BOM, artifactName, origin string) *cdxBom {
	components := []cdx.Component{}
	if bom.Components != nil {
		components = *bom.Components
		// first replace trivy properties - if any
		components = replaceTrivyProperties(components)
		// then normalize purls
		components = normalizePurls(components)
	}

	var originalRef string
	// replace the root component with the artifact name
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		originalRef = bom.Metadata.Component.BOMRef
		bom.Metadata.Component.BOMRef = artifactName
		bom.Metadata.Component.Name = artifactName
		bom.Metadata.Component.PackageURL = artifactName
		// remove the version string
		bom.Metadata.Component.Version = ""

		// make sure this component is part of the components slice
		found := false
		for i, comp := range components {
			if comp.BOMRef == originalRef {
				components[i] = *bom.Metadata.Component
				found = true
				break
			}
		}
		if !found {
			components = append(components, *bom.Metadata.Component)
		}
	}
	// add origin to components
	components = append(components, cdx.Component{
		Name:   origin,
		BOMRef: origin,
	})

	// remove all dependencies and rewrite those to SKIP invalid purls
	// this means A --> B (invalid purl) --> C (valid purl)
	// becomes A --> C
	dependencies := []cdx.Dependency{}
	if bom.Dependencies != nil {
		for _, dependency := range *bom.Dependencies {
			d := getShortCircuitDependencies(dependency.Ref, *bom.Dependencies)
			dependencies = append(dependencies, cdx.Dependency{
				Ref:          dependency.Ref,
				Dependencies: &d,
			})
		}
	}

	// create an artificial ROOT component which points to origin
	// which then points to all components which have no incoming edges
	artificialRoot := cdx.Dependency{
		Ref:          artifactName,
		Dependencies: &[]string{origin},
	}
	dependencies = append(dependencies, artificialRoot)
	// add another dependency from origin to all components which were required by root
	for _, d := range dependencies {
		if d.Ref == originalRef {
			dependencies = append(dependencies, cdx.Dependency{
				Ref:          origin,
				Dependencies: d.Dependencies,
			})
			break
		}
	}

	vulns := bom.Vulnerabilities
	if vulns != nil {
		// add those components to the bom as well
		for _, v := range *vulns {
			if v.Affects != nil {
				for _, affect := range *v.Affects {
					found := false
					for _, comp := range components {
						if comp.BOMRef == affect.Ref {
							found = true
							break
						}
					}
					if !found {
						// add a new component with just the ref
						newComp := cdx.Component{
							BOMRef:     affect.Ref,
							PackageURL: affect.Ref,
							Name:       affect.Ref,
						}
						components = append(components, newComp)
					}
					// add a dependency from origin to this component
					foundDep := false
					for _, d := range dependencies {
						if d.Ref == origin {
							// check if affect.Ref is already part of dependencies
							if slices.Contains(*d.Dependencies, affect.Ref) {
								foundDep = true
								break
							}
						}
					}
					if !foundDep {
						dependencies = append(dependencies, cdx.Dependency{
							Ref:          origin,
							Dependencies: &[]string{affect.Ref},
						})
					}
				}
			}
		}
	}

	bom.Dependencies = &dependencies
	bom.Components = &components

	return &cdxBom{bom: bom, origin: origin}
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

func ptr[T any](s T) *T {
	return &s
}

func ReplaceSubtree(completeSBOM SBOM, subTree SBOM) SBOM {
	result := cdx.NewBOM()
	result.Metadata = completeSBOM.GetMetadata()
	result.Components = ptr(append(*completeSBOM.GetComponents(), *subTree.GetComponents()...))
	result.Dependencies = &[]cdx.Dependency{}

	// Copy all dependencies from completeSBOM except the origin (we'll replace it)
	for _, d := range *completeSBOM.GetDependencies() {
		if d.Ref == subTree.GetOrigin() {
			// skip the original origin dependency, we'll replace it
			continue
		}
		result.Dependencies = ptr(append(*result.Dependencies, d))
	}

	// Add all dependencies from the subtree
	for _, d := range *subTree.GetDependencies() {
		// do not add the root dependency. Since we are working with normalized boms
		// this dependency is root --> Origin
		// BUT we have a new root we just created from the complete sbom.
		// we are adding this later
		if d.Ref == subTree.GetMetadata().Component.BOMRef {
			continue
		}
		result.Dependencies = ptr(append(*result.Dependencies, d))
	}

	// make sure root depends on origin
	root := result.Metadata.Component.BOMRef
	// find the dependencies slice for this root
	found := false
	for i, d := range *result.Dependencies {
		if d.Ref == root {
			// add origin as dependency if not already present
			if !slices.Contains(*d.Dependencies, subTree.GetOrigin()) {
				(*result.Dependencies)[i].Dependencies = ptr(append(*d.Dependencies, subTree.GetOrigin()))
			}
			found = true
			break
		}
	}
	if !found {
		// create a new dependency slice
		newDependency := cdx.Dependency{
			Ref:          root,
			Dependencies: ptr([]string{subTree.GetOrigin()}),
		}
		result.Dependencies = ptr(append(*result.Dependencies, newDependency))
	}

	componentsSlice := *result.Components
	componentsSlice = append(componentsSlice, *subTree.GetMetadata().Component)
	componentsSlice = append(componentsSlice, *completeSBOM.GetMetadata().Component)
	result.Components = &componentsSlice
	// unique dependencies
	result.Dependencies = ptr(uniqueDependencies(*result.Dependencies))

	return CdxBom(result)
}

func uniqueDependencies(dependencies []cdx.Dependency) []cdx.Dependency {
	// unique the dependencies based on the ref
	uniqueDependencies := make(map[string]cdx.Dependency)
	for _, d := range dependencies {
		if existing, ok := uniqueDependencies[d.Ref]; ok {
			// merge dependencies
			existingDeps := *existing.Dependencies
			for _, dep := range *d.Dependencies {
				if !slices.Contains(existingDeps, dep) {
					existingDeps = append(existingDeps, dep)
				}
			}
			existing.Dependencies = &existingDeps
			uniqueDependencies[d.Ref] = existing
		} else {
			uniqueDependencies[d.Ref] = d
		}
	}
	result := []cdx.Dependency{}
	for _, d := range uniqueDependencies {
		result = append(result, d)
	}
	return result
}
