package normalize

import (
	"fmt"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type CdxBom struct {
	tree            Tree[cdxBomNode]
	vulnerabilities *[]cdx.Vulnerability
}

func (bom *CdxBom) ReplaceRoot(newRoot cdxBomNode) {
	bom.tree.ReplaceRoot(newRoot)
}

func (bom *CdxBom) AddDirectChildWhichInheritsChildren(parent cdxBomNode, child cdxBomNode) {
	bom.tree.AddDirectChildWhichInheritsChildren(parent, child)
}

func (bom *CdxBom) AddSourceChildrenToTarget(source *TreeNode[cdxBomNode], target *TreeNode[cdxBomNode]) {
	bom.tree.AddSourceChildrenToTarget(source, target)
}

func (bom *CdxBom) ReplaceOrAddInformationSourceNode(subTree *TreeNode[cdxBomNode]) {
	// check if we have a node with the same ID already
	existingNodes := bom.GetInformationSourceNodes()
	for _, existingNode := range existingNodes {
		if existingNode.ID == subTree.ID {
			// replace the subtree
			bom.tree.ReplaceSubtree(subTree)
			return
		}
	}
	// if we reach here - we did not find an existing node - so we add the subtree to the root
	bom.AddChild(bom.tree.Root, subTree)
}

func (bom *CdxBom) GetInformationSourceNodes() []*TreeNode[cdxBomNode] {
	result := []*TreeNode[cdxBomNode]{}
	var visit func(node *TreeNode[cdxBomNode])
	visit = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		if node.element.Type() == NodeTypeSbomInformationSource || node.element.Type() == NodeTypeVexInformationSource {
			result = append(result, node)
		}
		for _, child := range node.Children {
			visit(child)
		}
	}

	visit(bom.tree.Root)
	return result
}

func (bom *CdxBom) AddChild(parent *TreeNode[cdxBomNode], child *TreeNode[cdxBomNode]) {
	bom.tree.AddChild(parent, child)
}

func (bom *CdxBom) CalculateDepth() map[string]int {
	depthMap := make(map[string]int)

	var visit func(node *TreeNode[cdxBomNode], depth int)
	visit = func(node *TreeNode[cdxBomNode], depth int) {
		if node == nil || node.element.nodeType == NodeTypeVexInformationSource {
			// do not run down vex paths
			return
		}
		depthMap[node.ID] = depth
		if node.element.Type() == NodeTypeComponent {
			depth++
		}

		for _, child := range node.Children {
			visit(child, depth)
		}
	}

	visit(bom.tree.Root, 1)
	// make sure the depth map is complete.
	// since we do not traverse vex paths - we might miss some nodes
	for id := range bom.tree.cursors {
		if _, exists := depthMap[id]; !exists {
			depthMap[id] = 1
		}
	}

	return depthMap
}
func (bom *CdxBom) CountParentTypes() map[string]map[nodeType]int {
	// multiple origins means we have the information from different sources
	// we need to traverse the tree and count the number of origin nodes we found along the way
	countMap := make(map[string]map[nodeType]int)

	var visit func(node *TreeNode[cdxBomNode])
	visit = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}

		for _, child := range node.Children {
			if _, exists := countMap[child.ID]; !exists {
				countMap[child.ID] = make(map[nodeType]int)
			}
			countMap[child.ID][node.element.Type()]++
			visit(child)
		}
	}

	visit(bom.tree.Root)

	return countMap
}

func (bom *CdxBom) InformationFromVexOrMultipleSBOMs() []string {
	result := []string{}
	countMap := bom.CountParentTypes()
	for id, typeCount := range countMap {
		if typeCount[NodeTypeSbomInformationSource] > 1 || typeCount[NodeTypeVexInformationSource] > 0 {
			result = append(result, id)
		}
	}
	return result
}

func (bom *CdxBom) GetComponentsIncludingFakeNodes() *[]cdx.Component {
	// collect the nodes REACHABLE from the root
	components := []cdx.Component{}
	alreadyAdded := make(map[string]bool)
	var visit func(node *TreeNode[cdxBomNode])
	visit = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		if !alreadyAdded[node.ID] {
			alreadyAdded[node.ID] = true
			components = append(components, *node.element.Data())
		}
		for _, child := range node.Children {
			visit(child)
		}
	}

	visit(bom.tree.Root)
	return &components
}

func (bom *CdxBom) GetDirectDependencies() *[]cdx.Dependency {
	dependencies := []cdx.Dependency{}
	for _, child := range bom.tree.Root.Children {
		deps := []string{}
		for _, grandChild := range child.Children {
			deps = append(deps, grandChild.ID)
		}

		dependencies = append(dependencies, cdx.Dependency{
			Ref:          child.ID,
			Dependencies: &deps,
		})
	}
	return &dependencies
}

func (bom *CdxBom) GetTransitiveDependencies() *[]cdx.Dependency {
	depMap := make(map[string][]string)
	var visit func(node *TreeNode[cdxBomNode])
	visit = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		for _, child := range node.Children {
			depMap[node.ID] = append(depMap[node.ID], child.ID)
			visit(child)
		}
	}

	for _, child := range bom.tree.Root.Children {
		visit(child)
	}

	dependencies := []cdx.Dependency{}
	for ref, deps := range depMap {
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &deps,
		})
	}
	return &dependencies
}

func (bom *CdxBom) GetDependenciesOfComponent(componentRef string) *cdx.Dependency {
	node := bom.tree.cursors[componentRef]
	if node == nil {
		return &cdx.Dependency{
			Ref:          componentRef,
			Dependencies: &[]string{},
		}
	}

	deps := []string{}
	for _, child := range node.Children {
		deps = append(deps, child.ID)
	}
	return &cdx.Dependency{
		Ref:          node.ID,
		Dependencies: &deps,
	}
}

func (bom *CdxBom) GetDependenciesIncludingFakeNodes() *[]cdx.Dependency {
	// collect the nodes reachable from the root and build dependencies
	depMap := make(map[string][]string)
	// Track all components (even those with no dependencies)
	allComponents := map[string]bool{
		bom.tree.Root.ID: true, // always include the root -> dependencies in the array, even if is no component
	}
	var visit func(parent *TreeNode[cdxBomNode], node *TreeNode[cdxBomNode])
	visit = func(parent *TreeNode[cdxBomNode], node *TreeNode[cdxBomNode]) {
		allComponents[node.ID] = true
		if !slices.Contains(depMap[parent.ID], node.ID) {
			depMap[parent.ID] = append(depMap[parent.ID], node.ID)
		}
		for _, child := range node.Children {
			visit(node, child)
		}
	}
	for _, child := range bom.tree.Root.Children {
		visit(bom.tree.Root, child)
	}
	dependencies := []cdx.Dependency{}
	for ref := range allComponents {
		deps := []string{}
		if existingDeps, ok := depMap[ref]; ok {
			deps = existingDeps
		}
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &deps,
		})
	}

	return &dependencies
}

func (bom *CdxBom) GetComponents() *[]cdx.Component {
	// collect the nodes REACHABLE from the root
	components := []cdx.Component{}
	alreadyAdded := make(map[string]bool)
	var visit func(node *TreeNode[cdxBomNode])
	visit = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		if node.element.Type() == NodeTypeComponent && !alreadyAdded[node.ID] {
			alreadyAdded[node.ID] = true
			components = append(components, *node.element.Data())
		}
		for _, child := range node.Children {
			visit(child)
		}
	}

	visit(bom.tree.Root)
	// always add the root component as well
	if !alreadyAdded[bom.tree.Root.ID] {
		components = append(components, *bom.tree.Root.element.Data())
	}
	return &components
}

func (bom *CdxBom) GetInformationSources() []string {
	nodes := bom.GetInformationSourceNodes()
	sources := []string{}
	for _, node := range nodes {
		sources = append(sources, node.ID)
	}
	return sources
}

func (bom *CdxBom) GetDependencies() *[]cdx.Dependency {
	// collect the nodes reachable from the root and build dependencies
	depMap := make(map[string][]string)
	// Track all components (even those with no dependencies)
	allComponents := map[string]bool{
		bom.tree.Root.ID: true, // always include the root -> dependencies in the array, even if is no component
	}
	var visit func(parent *TreeNode[cdxBomNode], node *TreeNode[cdxBomNode])
	visit = func(parent *TreeNode[cdxBomNode], node *TreeNode[cdxBomNode]) {
		if node.element.nodeType == NodeTypeComponent {
			allComponents[node.ID] = true
			if !slices.Contains(depMap[parent.ID], node.ID) {
				depMap[parent.ID] = append(depMap[parent.ID], node.ID)
			}
		}

		for _, child := range node.Children {
			if node.element.Type() != NodeTypeComponent {
				// pass the parent down - since this node is not a component
				visit(parent, child)
			} else {
				visit(node, child)
			}
		}
	}

	for _, child := range bom.tree.Root.Children {
		visit(bom.tree.Root, child)
	}
	dependencies := []cdx.Dependency{}
	for ref := range allComponents {
		deps := []string{}
		if existingDeps, ok := depMap[ref]; ok {
			deps = existingDeps
		}
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &deps,
		})
	}

	return &dependencies
}

func (bom *CdxBom) GetMetadata() *cdx.Metadata {
	return &cdx.Metadata{
		Component: bom.tree.Root.element.Component,
	}
}

func (bom *CdxBom) GetVulnerabilities() *[]cdx.Vulnerability {
	return bom.vulnerabilities
}

type nodeType string

const (
	NodeTypeComponent             nodeType = "component"
	NodeTypeSbomInformationSource nodeType = "sbom"
	NodeTypeVexInformationSource  nodeType = "vex"
	NodeTypeUnknown               nodeType = "unknown"
)

type cdxBomNode struct {
	*cdx.Component
	nodeType
}

func newCdxBomNode(component *cdx.Component) cdxBomNode {
	//  make sure to normalize the purl
	component = replaceTrivyProperties(component)
	component.PackageURL = normalizePurl(component.PackageURL)

	// if its a valid purl we expect this to be of type component -
	if strings.HasPrefix(component.BOMRef, "pkg:") || strings.HasPrefix(component.PackageURL, "pkg:") {
		return cdxBomNode{
			Component: component,
			nodeType:  NodeTypeComponent,
		}
	} else if strings.HasPrefix(component.BOMRef, fmt.Sprintf("%s:", NodeTypeSbomInformationSource)) {
		return cdxBomNode{
			Component: component,
			nodeType:  NodeTypeSbomInformationSource,
		}
	} else if strings.HasPrefix(component.BOMRef, fmt.Sprintf("%s:", NodeTypeVexInformationSource)) {
		return cdxBomNode{
			Component: component,
			nodeType:  NodeTypeVexInformationSource,
		}
	}

	return cdxBomNode{
		Component: component,
		nodeType:  NodeTypeUnknown,
	}
}

var _ Node = cdxBomNode{}

func (d cdxBomNode) GetID() string {
	return d.BOMRef
}

func (d cdxBomNode) Type() nodeType {
	return d.nodeType
}

func (d cdxBomNode) Data() *cdx.Component {
	return d.Component
}

func buildDependencyMap(dependencies []cdx.Dependency) map[string][]string {
	depMap := make(map[string][]string)
	for _, d := range dependencies {
		if d.Dependencies != nil {
			depMap[d.Ref] = append(depMap[d.Ref], *d.Dependencies...)
		}
	}
	return depMap
}

func newCdxBom(bom *cdx.BOM) *CdxBom {
	// convert components to sbomNodes
	// first make sure components exist
	if bom.Components == nil {
		bom.Components = &[]cdx.Component{}
	}
	if bom.Dependencies == nil {
		bom.Dependencies = &[]cdx.Dependency{}
	}

	sbomNodes := make([]cdxBomNode, 0, len(*bom.Components))
	for _, comp := range *bom.Components {
		sbomNodes = append(sbomNodes, newCdxBomNode(&comp))
	}

	// create nodes for the vulnerabilities as well
	vulns := normalizeVulnerabilities(bom.Vulnerabilities)
	vulnerableRefs := make(map[string]cdxBomNode)
	if vulns != nil {
		for _, v := range *vulns {
			if v.Affects == nil {
				continue
			}
			for _, affected := range *v.Affects {
				vulnerableRefs[normalizePurl(affected.Ref)] = newCdxBomNode(&cdx.Component{
					BOMRef:     normalizePurl(affected.Ref),
					Name:       normalizePurl(affected.Ref),
					PackageURL: normalizePurl(affected.Ref),
				})
				sbomNodes = append(sbomNodes, vulnerableRefs[normalizePurl(affected.Ref)])
			}
		}
	}

	// only remove dependencies and components which are not possible to visit from root
	tree := BuildDependencyTree(newCdxBomNode(bom.Metadata.Component), sbomNodes, buildDependencyMap(*bom.Dependencies))
	for ref, node := range vulnerableRefs {
		if !tree.Reachable(ref) {
			tree.AddChild(tree.Root, newNode(node))
		}
	}
	// set the vulnerabilities after normalization
	return &CdxBom{tree: tree, vulnerabilities: vulns}
}

func (bom *CdxBom) EjectVex() *cdx.BOM {
	b := cdx.BOM{
		SpecVersion:     cdx.SpecVersion1_6,
		BOMFormat:       "CycloneDX",
		XMLNS:           "http://cyclonedx.org/schema/bom/1.6",
		Version:         1,
		Components:      bom.GetComponents(),
		Dependencies:    bom.GetDependencies(),
		Metadata:        bom.GetMetadata(),
		Vulnerabilities: bom.GetVulnerabilities(),
	}

	return &b
}

func (bom *CdxBom) EjectSBOM() *cdx.BOM {
	b := cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		BOMFormat:    "CycloneDX",
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      1,
		Components:   bom.GetComponents(),
		Dependencies: bom.GetDependencies(),
		Metadata:     bom.GetMetadata(),
	}

	return &b
}

type minimalTreeNode struct {
	Name     string             `json:"name"`
	Children []*minimalTreeNode `json:"children"`
}

func (bom *CdxBom) EjectMinimalDependencyTree() *minimalTreeNode {
	var convert func(node *TreeNode[cdxBomNode]) *minimalTreeNode
	convert = func(node *TreeNode[cdxBomNode]) *minimalTreeNode {
		if node == nil {
			return nil
		}
		minNode := &minimalTreeNode{
			Name:     node.ID,
			Children: []*minimalTreeNode{},
		}
		for _, child := range node.Children {
			minChild := convert(child)
			if minChild != nil {
				minNode.Children = append(minNode.Children, minChild)
			}
		}
		return minNode
	}
	return convert(bom.tree.Root)
}

func replaceTrivyProperties(component *cdx.Component) *cdx.Component {
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
	return component
}

func normalizeVulnerabilities(vulns *[]cdx.Vulnerability) *[]cdx.Vulnerability {
	if vulns == nil {
		return &[]cdx.Vulnerability{}
	}
	for i, v := range *vulns {
		affects := v.Affects
		if affects == nil {
			continue
		}
		for j, affected := range *affects {
			(*(*vulns)[i].Affects)[j].Ref = normalizePurl(affected.Ref)
		}
	}
	return vulns
}

func RemoveOriginTypePrefixIfExists(origin string) (nodeType, string) {
	if after, ok := strings.CutPrefix(origin, fmt.Sprintf("%s:", NodeTypeVexInformationSource)); ok {
		return NodeTypeVexInformationSource, after
	} else if after, ok := strings.CutPrefix(origin, fmt.Sprintf("%s:", NodeTypeSbomInformationSource)); ok {
		return NodeTypeSbomInformationSource, after
	}
	return "", origin
}

func StructuralCompareCdxBoms(a, b *cdx.BOM) error {
	// check root ref is the same
	if a.Metadata == nil || b.Metadata == nil || a.Metadata.Component == nil || b.Metadata.Component == nil {
		return fmt.Errorf("one of the boms has no metadata or component")
	}
	if a.Metadata.Component.BOMRef != b.Metadata.Component.BOMRef {
		return fmt.Errorf("root bom refs do not match: %s != %s", a.Metadata.Component.BOMRef, b.Metadata.Component.BOMRef)
	}
	// check components count is the same
	if a.Components == nil || b.Components == nil {
		return fmt.Errorf("one of the boms has no components")
	}
	if len(*a.Components) != len(*b.Components) {
		return fmt.Errorf("component counts do not match: %d != %d", len(*a.Components), len(*b.Components))
	}
	// check dependencies count is the same
	if a.Dependencies == nil || b.Dependencies == nil {
		return fmt.Errorf("one of the boms has no dependencies")
	}
	if len(*a.Dependencies) != len(*b.Dependencies) {
		return fmt.Errorf("dependency counts do not match: %d != %d", len(*a.Dependencies), len(*b.Dependencies))
	}

	// check the component refs
	componentRefsA := make(map[string]bool)
	for _, comp := range *a.Components {
		componentRefsA[comp.BOMRef] = true
	}
	for _, comp := range *b.Components {
		if _, exists := componentRefsA[comp.BOMRef]; !exists {
			return fmt.Errorf("component ref %s not found in both boms", comp.BOMRef)
		}
	}

	// check the dependency refs
	dependencyRefsA := make(map[string][]string)
	for _, dep := range *a.Dependencies {
		dependencyRefsA[dep.Ref] = *dep.Dependencies
	}
	for _, dep := range *b.Dependencies {
		if _, exists := dependencyRefsA[dep.Ref]; !exists {
			return fmt.Errorf("dependency ref %s not found in both boms", dep.Ref)
		}
		// check the dependencies are the same
		depsA := dependencyRefsA[dep.Ref]
		depsB := *dep.Dependencies
		if len(depsA) != len(depsB) {
			return fmt.Errorf("dependency counts for ref %s do not match: %d != %d", dep.Ref, len(depsA), len(depsB))
		}
		depMap := make(map[string]bool)
		for _, d := range depsA {
			depMap[d] = true
		}
		for _, d := range depsB {
			if _, exists := depMap[d]; !exists {
				return fmt.Errorf("dependency %s for ref %s not found in both boms", d, dep.Ref)
			}
		}
	}

	return nil
}

func FromNormalizedCdxBom(bom *cdx.BOM, artifactName string) *CdxBom {
	cdxBom := newCdxBom(bom)
	newRoot := newCdxBomNode(&cdx.Component{
		BOMRef:     artifactName,
		Name:       artifactName,
		PackageURL: artifactName,
	})

	cdxBom.ReplaceRoot(newRoot)
	return cdxBom
}

func FromCdxBom(bom *cdx.BOM, artifactName, informationSource string) *CdxBom {
	bomType := NodeTypeSbomInformationSource
	if bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) > 0 {
		bomType = NodeTypeVexInformationSource
	}
	// check if the prefix already exists
	if !strings.HasPrefix(informationSource, fmt.Sprintf("%s:", bomType)) {
		informationSource = fmt.Sprintf("%s:%s", bomType, informationSource)
	}

	cdxBom := newCdxBom(bom)
	newRoot := newCdxBomNode(&cdx.Component{
		BOMRef:     artifactName,
		Name:       artifactName,
		PackageURL: artifactName,
	})

	informationSourceNode := newCdxBomNode(&cdx.Component{
		BOMRef:     informationSource,
		Name:       informationSource,
		PackageURL: informationSource,
	})

	cdxBom.ReplaceRoot(newRoot)
	cdxBom.AddDirectChildWhichInheritsChildren(
		newRoot,
		informationSourceNode,
	)

	return cdxBom
}

func MergeCdxBoms(metadata *cdx.Metadata, boms ...*CdxBom) *CdxBom {
	merged := &cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		BOMFormat:    "CycloneDX",
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      1,
		Components:   &[]cdx.Component{},
		Dependencies: &[]cdx.Dependency{},
		Metadata:     metadata,
	}

	vulnMap := make(map[string]cdx.Vulnerability)

	newBom := newCdxBom(merged)
	for _, bom := range boms {
		if bom == nil {
			continue
		}
		newBom.AddChild(newBom.tree.Root, bom.tree.Root)
		if bom.vulnerabilities != nil {
			for _, v := range *bom.vulnerabilities {
				vulnMap[v.ID] = v
			}
		}
	}

	vulns := []cdx.Vulnerability{}
	for _, v := range vulnMap {
		vulns = append(vulns, v)
	}
	newBom.vulnerabilities = &vulns

	return newBom
}

func ptr[T any](s T) *T {
	return &s
}
