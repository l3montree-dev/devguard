package normalize

import (
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
)

const ROOT = "ROOT"

// A normalized CycloneDX BOM always has the following structure
// - Root Node (ROOT, see const)
// --- Artifact Nodes (one per artifact in the asset version)
// ----- Information Source Nodes (one or more, representing SBOMs or VEX documents)
// --------- Component Nodes (the actual components, dependencies)
type CdxBom struct {
	tree            Tree[cdxBomNode]
	vulnerabilities *[]cdx.Vulnerability
}

func (bom *CdxBom) ReplaceRoot(newRoot cdxBomNode) {
	bom.tree.ReplaceRoot(newRoot)
}

func getDependencyRefsNotIncludedInAnySubtree(dependencies *[]cdx.Dependency) *[]string {
	// Collect all dependency refs
	dependencyRefsNotInAnySubtree := make(map[string]struct{}, len(*dependencies))
	for _, dependency := range *dependencies {
		dependencyRefsNotInAnySubtree[dependency.Ref] = struct{}{}
	}

	// Remove refs that are children of any dependency (they are in a subtree)
	for _, dep := range *dependencies {
		if dep.Dependencies != nil {
			for _, child := range *dep.Dependencies {
				delete(dependencyRefsNotInAnySubtree, child)
			}
		}
	}

	// Collect remaining refs (these are not in any subtree)
	newDependencyRefs := make([]string, 0, len(dependencyRefsNotInAnySubtree))
	for depRef := range dependencyRefsNotInAnySubtree {
		newDependencyRefs = append(newDependencyRefs, depRef)
	}

	return &newDependencyRefs
}

func (bom *CdxBom) AddDirectChildWhichInheritsChildren(parent cdxBomNode, child cdxBomNode) {
	bom.tree.AddDirectChildWhichInheritsChildren(parent, child)
}

func (bom *CdxBom) AddSourceChildrenToTarget(source *TreeNode[cdxBomNode], target *TreeNode[cdxBomNode]) {
	bom.tree.AddSourceChildrenToTarget(source, target)
}

func (bom *CdxBom) ReplaceOrAddArtifact(subTree *CdxBom) {
	// check if already exists
	for _, existingArtifactNode := range bom.tree.Root.Children {
		if existingArtifactNode.ID == subTree.tree.Root.ID {
			// replace the subtree
			bom.tree.ReplaceSubtree(subTree.tree.Root)
			return
		}
	}
	// if we reach here - we did not find an existing node - so we add the subtree to the root
	bom.AddChild(bom.tree.Root, subTree.tree.Root)
}

func (bom *CdxBom) ReplaceOrAddInformationSourceNode(subTree *TreeNode[cdxBomNode]) {
	// its only allowed to call this function if bom.tree.Root is an artifact
	if bom.tree.Root == nil || bom.tree.Root.element.Type() != NodeTypeArtifact {
		panic("ReplaceOrAddInformationSourceNode called on 'not artifact' scoped bom. Use ExtractArtifactBom before")
	}

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
	if bom == nil {
		return []*TreeNode[cdxBomNode]{}
	}
	result := []*TreeNode[cdxBomNode]{}
	var visit func(node *TreeNode[cdxBomNode])
	visit = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		if node.element.Type() == NodeTypeSbomInformationSource || node.element.Type() == NodeTypeVexInformationSource || node.element.Type() == NodeTypeCSAFInformationSource {
			result = append(result, node)
		}
		for _, child := range node.Children {
			visit(child)
		}
	}

	if bom.tree.Root == nil {
		return result
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
		if node == nil || node.element.nodeType == NodeTypeVexInformationSource || node.element.nodeType == NodeTypeCSAFInformationSource {
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
		if typeCount[NodeTypeSbomInformationSource] > 1 || typeCount[NodeTypeVexInformationSource] > 0 || (typeCount[NodeTypeCSAFInformationSource] > 0) {
			result = append(result, id)
		}
	}
	return result
}

func (bom *CdxBom) GetAllParentNodes(nodeID string) []string {
	// traverse the tree downwards and find all parents of the given nodeID
	result := []string{}
	var visit func(node *TreeNode[cdxBomNode], parents []string)
	visit = func(node *TreeNode[cdxBomNode], parents []string) {
		if node == nil {
			return
		}
		if node.ID == nodeID {
			result = append(result, parents...)
			return
		}
		newParents := append(parents, node.ID)
		for _, child := range node.Children {
			visit(child, newParents)
		}
	}
	visit(bom.tree.Root, []string{})
	return result
}

func (bom *CdxBom) GetComponentIDsIncludingFakeNodes() map[string]struct{} {
	components := bom.GetComponentsIncludingFakeNodes()
	componentIDs := make(map[string]struct{})
	for _, component := range *components {
		id := GetComponentID(component)
		componentIDs[id] = struct{}{}
	}
	return componentIDs
}

// GetComponentNode returns the tree node for a given component ID
func (bom *CdxBom) GetComponentNode(componentID string) (*TreeNode[cdxBomNode], bool) {
	if bom == nil || bom.tree.cursors == nil {
		return nil, false
	}
	node, exists := bom.tree.cursors[componentID]
	return node, exists
}

// FindAllPathsToComponent finds all dependency paths from root to the specified component.
// Returns a minimal tree containing only the paths that lead to the target component.
//
// To filter by artifact, first call ExtractArtifactBom() to get a filtered bom:
//
//	artifactBom := fullBom.ExtractArtifactBom("manifest.json")
//	paths := artifactBom.FindAllPathsToComponent("pkg:npm/lodash@4.17.21")
func (bom *CdxBom) FindAllPathsToComponent(componentID string) *minimalTreeNode {
	if bom == nil || bom.tree.Root == nil {
		return nil
	}

	// Build a minimal tree containing only paths to the target component
	var buildMinimalTree func(node *TreeNode[cdxBomNode], visited map[string]bool) *minimalTreeNode
	buildMinimalTree = func(node *TreeNode[cdxBomNode], visited map[string]bool) *minimalTreeNode {
		if node == nil {
			return nil
		}

		// Check for cycles
		if visited[node.ID] {
			return nil
		}

		// Mark as visited for this path
		newVisited := make(map[string]bool)
		maps.Copy(newVisited, visited)
		newVisited[node.ID] = true

		// Check if this is the target component
		if node.ID == componentID {
			return &minimalTreeNode{
				Name:     node.ID,
				Children: []*minimalTreeNode{},
			}
		}

		// Recursively check children
		var validChildren []*minimalTreeNode
		for _, child := range node.Children {
			minChild := buildMinimalTree(child, newVisited)
			if minChild != nil {
				validChildren = append(validChildren, minChild)
			}
		}

		// If any child leads to the target, include this node
		if len(validChildren) > 0 {
			return &minimalTreeNode{
				Name:     node.ID,
				Children: validChildren,
			}
		}

		return nil
	}

	return buildMinimalTree(bom.tree.Root, make(map[string]bool))
}

// ExtractArtifactBom returns a new CdxBom containing only the subtree rooted at the specified artifact.
// The artifact becomes the new root of the returned bom.
// Returns nil if the artifact is not found.
//
// Example usage:
//
//	fullBom := assetVersionService.LoadFullSBOM(...)
//	artifactBom := fullBom.ExtractArtifactBom("manifest.json")
//	paths := artifactBom.FindAllPathsToComponent("pkg:npm/lodash@4.17.21")
func (bom *CdxBom) ExtractArtifactBom(artifactName string) *CdxBom {
	if bom == nil || bom.tree.Root == nil {
		return nil
	}

	artifactID := "artifact:" + artifactName
	artifactNode, exists := bom.tree.cursors[artifactID]
	if !exists {
		return nil
	}

	// Create a new CdxBom with the artifact as root
	newBom := &CdxBom{
		tree: Tree[cdxBomNode]{
			Root:    artifactNode, // will copy the all of the children as well
			cursors: make(map[string]*TreeNode[cdxBomNode]),
		},
		vulnerabilities: bom.vulnerabilities,
	}

	// Populate cursors for the subtree
	var addToCursors func(node *TreeNode[cdxBomNode])
	addToCursors = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		newBom.tree.cursors[node.ID] = node
		for _, child := range node.Children {
			addToCursors(child)
		}
	}
	addToCursors(artifactNode)

	return newBom
}

func (bom *CdxBom) GetSubtree(nodeID string) (Tree[cdxBomNode], error) {
	// returns the subtree rooted at the given nodeID
	if bom == nil || bom.tree.Root == nil {
		return Tree[cdxBomNode]{}, fmt.Errorf("bom or bom tree is nil")
	}

	subtreeRoot, exists := bom.tree.cursors[nodeID]
	if !exists {
		return Tree[cdxBomNode]{}, fmt.Errorf("nodeID %s not found in bom", nodeID)
	}

	newTree := Tree[cdxBomNode]{
		Root:    subtreeRoot,
		cursors: make(map[string]*TreeNode[cdxBomNode]),
	}

	// Populate cursors for the subtree
	var addToCursors func(node *TreeNode[cdxBomNode])
	addToCursors = func(node *TreeNode[cdxBomNode]) {
		if node == nil {
			return
		}
		newTree.cursors[node.ID] = node
		for _, child := range node.Children {
			addToCursors(child)
		}
	}
	addToCursors(subtreeRoot)

	return newTree, nil
}

// GetSubtreeNodeIDs returns all node IDs reachable from the specified artifact root.
// This includes the artifact node itself and all its descendants.
// For a filtered CdxBom, use ExtractArtifactBom() instead.
func (bom *CdxBom) GetSubtreeNodeIDs(nodeID string) ([]string, error) {
	tree, err := bom.GetSubtree(nodeID)
	if err != nil {
		return nil, err
	}

	// we can use the cursors of the subtree tree
	nodeIDs := make([]string, 0, len(tree.cursors))
	for id := range tree.cursors {
		nodeIDs = append(nodeIDs, id)
	}
	return nodeIDs, nil
}

// GetComponentsForArtifact returns all component dependencies that belong to the specified artifact.
// This is useful for filtering the full SBOM to just one artifact's dependencies.
func (bom *CdxBom) GetComponentsForArtifact(artifactName string) ([]cdx.Component, error) {
	subtreeIDs, err := bom.GetSubtreeNodeIDs(artifactName)
	if err != nil {
		return nil, err
	}

	idSet := make(map[string]bool, len(subtreeIDs))
	for _, id := range subtreeIDs {
		idSet[id] = true
	}

	var components []cdx.Component
	for _, node := range bom.tree.cursors {
		if idSet[node.ID] && node.element.Type() == NodeTypeComponent {
			components = append(components, *node.element.Data())
		}
	}
	return components, nil
}

// this returns direct csaf children of csaf information source nodes
// since csaf does not scope transitive dependencies
// but we might be able to redistribute found cves to the subtree reachable from those purls.
func (bom *CdxBom) GetCsafRootPurls() []string {
	// iterate the tree and find all nodes which have a direct csaf parent
	result := []string{}
	var visit func(node *TreeNode[cdxBomNode], parentType nodeType)
	visit = func(node *TreeNode[cdxBomNode], parentType nodeType) {
		if node == nil {
			return
		}
		if parentType == NodeTypeCSAFInformationSource && node.element.Type() == NodeTypeComponent {
			result = append(result, node.ID)
		}
		for _, child := range node.Children {
			visit(child, node.element.Type())
		}
	}

	visit(bom.tree.Root, "")
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
	if bom == nil {
		return &[]cdx.Component{}
	}
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
	return &components
}

// GetLicenseDistribution returns a map of license ID to count of components with that license.
// Components without a license are counted as "unknown".
func (bom *CdxBom) GetLicenseDistribution() map[string]int {
	if bom == nil {
		return map[string]int{}
	}

	distribution := make(map[string]int)
	components := bom.GetComponents()

	for _, component := range *components {
		license := "unknown"
		if component.Licenses != nil && len(*component.Licenses) > 0 {
			// Use the first license choice's ID or expression
			licenseChoice := (*component.Licenses)[0]
			if licenseChoice.License != nil && licenseChoice.License.ID != "" {
				license = licenseChoice.License.ID
			} else if licenseChoice.License != nil && licenseChoice.License.Name != "" {
				license = licenseChoice.License.Name
			} else if licenseChoice.Expression != "" {
				license = licenseChoice.Expression
			}
		}
		distribution[license]++
	}

	return distribution
}

func (bom *CdxBom) GetInformationSources() []string {
	if bom == nil {
		return []string{}
	}
	nodes := bom.GetInformationSourceNodes()
	sources := []string{}
	for _, node := range nodes {
		sources = append(sources, node.ID)
	}
	return sources
}

func (bom *CdxBom) GetDependencies() *[]cdx.Dependency {
	if bom == nil {
		return &[]cdx.Dependency{}
	}
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
		// since we pass the root as parent, IT WILL ALWAYS BE part of the dependencies slice
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

func (bom *CdxBom) GetVulnerabilities() *[]cdx.Vulnerability {
	if bom == nil {
		return &[]cdx.Vulnerability{}
	}
	return bom.vulnerabilities
}

type nodeType string

const (
	NodeTypeComponent             nodeType = "component"
	NodeTypeSbomInformationSource nodeType = "sbom"
	NodeTypeVexInformationSource  nodeType = "vex"
	NodeTypeCSAFInformationSource nodeType = "csaf"
	NodeTypeArtifact              nodeType = "artifact"
	NodeTypeUnknown               nodeType = "unknown"
)

type cdxBomNode struct {
	*cdx.Component
	nodeType
}

func newCdxBomNode(component *cdx.Component) cdxBomNode {
	//  make sure to normalize the purl
	if component.PackageURL != "" {
		component.PackageURL = normalizePurl(component.PackageURL)
	}

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
		// check if its a csaf information source
		return cdxBomNode{
			Component: component,
			nodeType:  NodeTypeVexInformationSource,
		}
	} else if strings.HasPrefix(component.BOMRef, fmt.Sprintf("%s:", NodeTypeCSAFInformationSource)) {
		return cdxBomNode{
			Component: component,
			nodeType:  NodeTypeCSAFInformationSource,
		}
	} else if strings.HasPrefix(component.BOMRef, fmt.Sprintf("%s:", NodeTypeArtifact)) {
		return cdxBomNode{
			Component: component,
			nodeType:  NodeTypeArtifact,
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

type CdxComponent interface {
	GetID() string
	GetDependentID() *string
	ToCdxComponent(componentLicenseOverwrites map[string]string) cdx.Component
}

func FromVulnerabilities(vulns []cdx.Vulnerability) *CdxBom {
	bom := cdx.BOM{}
	bom.Vulnerabilities = &vulns
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef: ROOT,
			Name:   ROOT,
		},
	}
	return newCdxBom(&bom)
}

// This function expects the components to already have a normalized structure
// this means it includes artifact nodes and information source nodes
// AND the linking between artifacts, information sources and components is already done
func FromComponents(components []CdxComponent, licenseOverwrites map[string]string) *CdxBom {
	bom := cdx.BOM{}
	// add all components (root is created in fromNormalizedCdxBom)
	bomComponents := make([]cdx.Component, 0, len(components))
	processedComponents := make(map[string]struct{}, len(components))

	for _, component := range components {
		if _, alreadyProcessed := processedComponents[component.GetID()]; alreadyProcessed {
			continue
		}
		processedComponents[component.GetID()] = struct{}{}
		bomComponents = append(bomComponents, component.ToCdxComponent(licenseOverwrites))
	}

	// just add all dependencies
	// the sbom will be normalized afterwards
	dependencyMap := make(map[string][]string)
	for _, c := range components {
		var purl string
		if c.GetDependentID() != nil {
			purl = *c.GetDependentID()
		} else {
			// if the dependant ID is nil, its a direct dependency from root.
			// we are NOT storing ROOT inside the database but NULL instead.
			// this if statement converts NULL to ROOT for the purpose of building the bom
			purl = ROOT
		}
		dependencyMap[purl] = append(dependencyMap[purl], c.GetID())
	}

	// build up the dependencies
	bomDependencies := make([]cdx.Dependency, 0, len(dependencyMap))
	for k, v := range dependencyMap {
		bomDependencies = append(bomDependencies, cdx.Dependency{
			Ref:          k,
			Dependencies: &v,
		})
	}
	bom.Dependencies = &bomDependencies
	bom.Components = &bomComponents
	// what is the ROOT of this? Actually its the asset version itself.
	// but since we do not store that as a component - we create a fake root component
	// this will be the root of the tree structure.
	rootComponent := cdx.Component{
		BOMRef: ROOT,
		Name:   ROOT,
	}
	bom.Metadata = &cdx.Metadata{
		Component: &rootComponent,
	}

	return newCdxBom(&bom)
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
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	if bom.Metadata.Component == nil {
		bom.Metadata.Component = &cdx.Component{
			BOMRef: ROOT,
			Name:   ROOT,
		}
		// if no root can be found, ALL components are unvisitable from root
		// this gets handled in the tree building below
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

	// check if the root has children; if not, we need to add dependency refs which are not part of any subtree as direct children of root
	if len(tree.Root.Children) == 0 {
		newDep := getDependencyRefsNotIncludedInAnySubtree(bom.Dependencies)

		//check if the root is part of the new dependencies - if so, remove it and warn
		if slices.Contains(*newDep, bom.Metadata.Component.BOMRef) {
			slog.Warn("root component had no children - but was part of dependencies - removing from direct dependencies to avoid cycle", "rootRef", bom.Metadata.Component.BOMRef)
			filteredDeps := []string{}
			for _, dep := range *newDep {
				if dep != bom.Metadata.Component.BOMRef {
					filteredDeps = append(filteredDeps, dep)
				}
			}
			newDep = &filteredDeps
		}
		*bom.Dependencies = append(*bom.Dependencies, cdx.Dependency{
			Ref:          bom.Metadata.Component.BOMRef,
			Dependencies: newDep,
		})

		// rebuild the tree
		tree = BuildDependencyTree(newCdxBomNode(bom.Metadata.Component), sbomNodes, buildDependencyMap(*bom.Dependencies))
		for ref, node := range vulnerableRefs {
			if !tree.Reachable(ref) {
				tree.AddChild(tree.Root, newNode(node))
			}
		}
	}
	// set the vulnerabilities after normalization
	return &CdxBom{tree: tree, vulnerabilities: vulns}
}

func (bom *CdxBom) calculateExternalURLs(docURL string, metadata BOMMetadata) (string, string) {
	dashboardURL := ""
	if metadata.FrontendURL != "" && metadata.OrgSlug != "" && metadata.ProjectSlug != "" && metadata.AssetSlug != "" {
		dashboardURL = fmt.Sprintf("%s/%s/projects/%s/assets/%s", metadata.FrontendURL, metadata.OrgSlug, metadata.ProjectSlug, metadata.AssetSlug)
	}

	if metadata.AssetVersionSlug != "" {
		docURL = fmt.Sprintf("%s?ref=%s", docURL, url.QueryEscape(metadata.AssetVersionSlug))
		if dashboardURL != "" {
			dashboardURL = fmt.Sprintf("%s/refs/%s", dashboardURL, url.QueryEscape(metadata.AssetVersionSlug))
		}
	} else {
		if dashboardURL != "" {
			dashboardURL = fmt.Sprintf("%s/refs/main", dashboardURL)
		}
	}

	if metadata.AssetVersionSlug != "" && metadata.ArtifactName != "" {
		docURL = fmt.Sprintf("%s&artifactName=%s", docURL, url.QueryEscape(metadata.ArtifactName))
		if dashboardURL != "" {
			dashboardURL = fmt.Sprintf("%s?artifact=%s", dashboardURL, url.QueryEscape(metadata.ArtifactName))
		}
	} else if metadata.ArtifactName != "" {
		docURL = fmt.Sprintf("%s?artifactName=%s", docURL, url.QueryEscape(metadata.ArtifactName))
	}

	return docURL, dashboardURL
}

func (bom *CdxBom) EjectVex(metadata BOMMetadata) *cdx.BOM {
	var externalRefs *[]cdx.ExternalReference
	if metadata.AddExternalReferences && metadata.AssetID != nil {
		apiURL := os.Getenv("API_URL")
		vexURL := fmt.Sprintf("%s/api/v1/public/%s/vex.json", apiURL, metadata.AssetID.String())

		vexURL, dashboardURL := bom.calculateExternalURLs(vexURL, metadata)

		externalRefs = &[]cdx.ExternalReference{{
			URL:     vexURL,
			Comment: "Up to date Vulnerability exploitability information.",
			Type:    cdx.ERTypeExploitabilityStatement,
		}}

		if dashboardURL != "" {
			*externalRefs = append(*externalRefs, cdx.ExternalReference{
				URL:     dashboardURL,
				Comment: "Dynamic analysis report",
				Type:    cdx.ERTypeDynamicAnalysisReport,
			})
		}
	}

	// check if valid purl
	p, err := packageurl.FromString(metadata.ArtifactName)
	pURL := ""
	if err == nil {
		pURL = p.String()
	}

	rootCdxComponent := &cdx.Component{
		BOMRef:     metadata.ArtifactName,
		Name:       metadata.ArtifactName,
		Type:       cdx.ComponentTypeApplication,
		PackageURL: pURL,
	}

	bom.tree.Root.ID = metadata.ArtifactName
	bom.tree.Root.element = cdxBomNode{
		Component: rootCdxComponent,
		nodeType:  NodeTypeComponent, // otherwise it will be excluded from the components list
	}

	b := cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		BOMFormat:    "CycloneDX",
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      1,
		Components:   bom.GetComponents(),
		Dependencies: bom.GetDependencies(),
		Metadata: &cdx.Metadata{
			Component: rootCdxComponent,
		},
		Vulnerabilities:    bom.GetVulnerabilities(),
		ExternalReferences: externalRefs,
	}

	return &b
}

type BOMMetadata struct {
	AssetVersionSlug      string
	AssetSlug             string
	ProjectSlug           string
	OrgSlug               string
	FrontendURL           string
	ArtifactName          string
	AssetID               *uuid.UUID
	AddExternalReferences bool
}

func (bom *CdxBom) EjectSBOM(metadata BOMMetadata) *cdx.BOM {
	var externalRefs *[]cdx.ExternalReference
	if metadata.AddExternalReferences && metadata.AssetID != nil {
		apiURL := os.Getenv("API_URL")
		sbomURL := fmt.Sprintf("%s/api/v1/public/%s/sbom.json", apiURL, metadata.AssetID.String())

		sbomURL, dashboardURL := bom.calculateExternalURLs(sbomURL, metadata)

		externalRefs = &[]cdx.ExternalReference{{
			URL:     sbomURL,
			Comment: "Up to date software bill of material and license information.",
			Type:    cdx.ERTypeBOM,
		}}

		if dashboardURL != "" {
			*externalRefs = append(*externalRefs, cdx.ExternalReference{
				URL:     dashboardURL,
				Comment: "Dynamic analysis report",
				Type:    cdx.ERTypeDynamicAnalysisReport,
			})
		}
	}
	// check if valid purl
	p, err := packageurl.FromString(metadata.ArtifactName)
	pURL := ""
	if err == nil {
		pURL = p.String()
	}

	rootCdxComponent := &cdx.Component{
		BOMRef:     metadata.ArtifactName,
		Name:       metadata.ArtifactName,
		Type:       cdx.ComponentTypeApplication,
		PackageURL: pURL,
	}

	bom.tree.Root.ID = metadata.ArtifactName
	bom.tree.Root.element = cdxBomNode{
		Component: rootCdxComponent,
		nodeType:  NodeTypeComponent, // otherwise it will be excluded from the components list
	}

	b := cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		BOMFormat:    "CycloneDX",
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      1,
		Components:   bom.GetComponents(),
		Dependencies: bom.GetDependencies(),
		Metadata: &cdx.Metadata{
			Component: rootCdxComponent,
		},
		ExternalReferences: externalRefs,
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

// GetRootID returns the ID of the root node of the BOM tree
func (bom *CdxBom) GetRootID() string {
	if bom == nil || bom.tree.Root == nil {
		return ""
	}
	return bom.tree.Root.ID
}

// NodeIDsAndEdges returns all node IDs and edges in the BOM tree
func (bom *CdxBom) NodeIDsAndEdges() FlatTree {
	return bom.tree.NodeIDsAndEdges()
}

// NewEmptyArtifactBom creates a new CdxBom with just an artifact root node
// This is used when creating a new artifact that doesn't exist yet
func NewEmptyArtifactBom(artifactName string) *CdxBom {
	artifactID := "artifact:" + artifactName
	artifactNode := &TreeNode[cdxBomNode]{
		ID: artifactID,
		element: cdxBomNode{
			Component: &cdx.Component{BOMRef: artifactID},
			nodeType:  NodeTypeArtifact,
		},
		Children: []*TreeNode[cdxBomNode]{},
	}

	return &CdxBom{
		tree: Tree[cdxBomNode]{
			Root:    artifactNode,
			cursors: map[string]*TreeNode[cdxBomNode]{artifactID: artifactNode},
		},
		vulnerabilities: &[]cdx.Vulnerability{},
	}
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
	} else if after, ok := strings.CutPrefix(origin, fmt.Sprintf("%s:", NodeTypeCSAFInformationSource)); ok {
		return NodeTypeCSAFInformationSource, after
	} else if after, ok := strings.CutPrefix(origin, fmt.Sprintf("%s:", NodeTypeArtifact)); ok {
		return NodeTypeArtifact, after
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

// example: csaf:pkg:npm/%40angular/animation@12.3.1:https://example.com/csaf/1234
var csafInformationSourceRegex = regexp.MustCompile(`^(?:csaf:)?(pkg:[a-zA-Z0-9\/\.\-_]+(?:@[a-zA-Z0-9\.\-_]+)?):(https?:\/\/[^\s\/$.?#][^\s]*)$`)

func isCSAFInformationSource(informationSource string) bool {
	return csafInformationSourceRegex.MatchString(informationSource)
}

// This function builds a normalized CdxBom structure
// This means: Root --> Artifact --> InformationSource --> Components
// Thus this function needs the artifact name and information source as parameters
func FromCdxBom(bom *cdx.BOM, artifactName, informationSource string) *CdxBom {
	// default to sbom
	bomType := NodeTypeSbomInformationSource
	// check if a purl is inside the string - if so we treat it as a csaf information source
	if isCSAFInformationSource(informationSource) {
		bomType = NodeTypeCSAFInformationSource
	} else if bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) > 0 {
		bomType = NodeTypeVexInformationSource
	}

	// check if the prefix already exists
	if !strings.HasPrefix(informationSource, fmt.Sprintf("%s:", bomType)) {
		informationSource = fmt.Sprintf("%s:%s", bomType, informationSource)
	}

	// build the artifact node
	artifactNode := newCdxBomNode(&cdx.Component{
		BOMRef: fmt.Sprintf("artifact:%s", artifactName),
		Name:   artifactName,
		Type:   "artifact",
	})

	// build the information source node
	informationSourceNode := newCdxBomNode(&cdx.Component{
		BOMRef: informationSource,
		Name:   informationSource,
	})

	if bom.Dependencies != nil {
		for i := range *bom.Dependencies {
			if (*bom.Dependencies)[i].Ref == "" {
				(*bom.Dependencies)[i].Ref = informationSource
			}
		}
	}

	cdxBom := newCdxBom(bom)

	// add the artifact and information source nodes to the tree Root --> Artifact --> InformationSource
	cdxBom.AddDirectChildWhichInheritsChildren(
		cdxBom.tree.Root.element,
		artifactNode,
	)
	cdxBom.AddDirectChildWhichInheritsChildren(
		artifactNode,
		informationSourceNode,
	)

	return cdxBom
}

func MergeCdxBoms(boms ...*CdxBom) *CdxBom {
	merged := &cdx.BOM{
		SpecVersion:  cdx.SpecVersion1_6,
		BOMFormat:    "CycloneDX",
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      1,
		Components:   &[]cdx.Component{},
		Dependencies: &[]cdx.Dependency{},
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef: ROOT,
				Name:   ROOT,
			},
		},
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
