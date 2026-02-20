// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package normalize

import (
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
)

func SanitizeExternalReferencesURL(url string) string {
	// when attesting with cosign, & get replaced with \u0026
	// we need to revert that here
	sanitizedURL := strings.ReplaceAll(url, `\u0026`, `&`)
	return sanitizedURL
}

// Path represents a vulnerability path through the dependency graph.
// It can contain both structural nodes (root, artifact, info sources) and component nodes (PURLs).
type Path []string

// ToStringSlice returns all nodes in the path, including fake/structural nodes.
func (p Path) ToStringSlice() []string {
	return []string(p)
}

// String returns a comma-separated string of all nodes in the path.
func (p Path) String() string {
	return strings.Join(p, ",")
}

// =============================================================================
// NODE TYPES
// =============================================================================

// GraphNodeType identifies what kind of node this is in the graph.
type GraphNodeType string

const (
	GraphNodeTypeRoot       GraphNodeType = "root"
	GraphNodeTypeArtifact   GraphNodeType = "artifact"
	GraphNodeTypeInfoSource GraphNodeType = "infosource"
	GraphNodeTypeComponent  GraphNodeType = "component"
)

// InfoSourceType indicates where component information came from.
type InfoSourceType string

const (
	InfoSourceSBOM InfoSourceType = "sbom"
)

// =============================================================================
// GRAPH NODE
// =============================================================================

// GraphNode represents any node in the SBOM graph.
// All nodes (root, artifacts, info sources, components) share this structure.
type GraphNode struct {
	BOMRef string        // Unique identifier
	Type   GraphNodeType // What kind of node this is

	// For components, this holds the full CycloneDX component data
	Component *cdx.Component

	// InfoSource-specific fields (only set for GraphNodeTypeInfoSource)
	InfoType InfoSourceType
}

// =============================================================================
// SBOM GRAPH
// =============================================================================

// SBOMGraph is a directed graph representing a software bill of materials.
//
// Structure:
//
//	ROOT
//	└── artifact:my-app
//	    └── sbom:package-lock.json
//	        └── pkg:npm/lodash@4.17.21
//	            └── pkg:npm/some-dep@1.0.0
//
// All nodes live in the same graph. Scoping is done by traversing from a specific node.
type SBOMGraph struct {
	nodes map[string]*GraphNode          // id -> node
	edges map[string]map[string]struct{} // parent id -> set of child ids

	vulnerabilities map[string]*cdx.Vulnerability // vuln ID -> vulnerability

	rootID string // ID of the root node (constant: "ROOT")

	scopeID string // The id of the current scope node
}

type VexReport struct {
	Report *cdx.BOM
	Source string
}

func validateVexReport(report *cdx.BOM) error {
	if report.Metadata == nil || report.Metadata.Component == nil {
		return fmt.Errorf("invalid VEX report: missing metadata.component")
	}
	if report.Metadata.Component.PackageURL == "" {
		return fmt.Errorf("invalid VEX report: root component must have a PackageURL")
	}
	return nil
}

func NewVexReport(report *cdx.BOM, source string) (*VexReport, error) {
	if err := validateVexReport(report); err != nil {
		return nil, err
	}

	return &VexReport{
		Report: report,
		Source: source,
	}, nil
}

func edgesToDepMap(edges map[string]map[string]struct{}) map[string][]string {
	depMap := make(map[string][]string)
	for parent, children := range edges {
		for child := range children {
			depMap[parent] = append(depMap[parent], child)
		}
	}
	return depMap
}

const GraphRootNodeID = "ROOT"

// =============================================================================
// CONSTRUCTORS
// =============================================================================

// NewSBOMGraph creates an empty graph with a root node.
func NewSBOMGraph() *SBOMGraph {
	g := &SBOMGraph{
		nodes:           make(map[string]*GraphNode),
		edges:           make(map[string]map[string]struct{}),
		vulnerabilities: make(map[string]*cdx.Vulnerability),
		rootID:          GraphRootNodeID,
		scopeID:         GraphRootNodeID,
	}
	// Always create root node
	g.nodes[GraphRootNodeID] = &GraphNode{BOMRef: GraphRootNodeID, Type: GraphNodeTypeRoot, Component: &cdx.Component{
		PackageURL: "", // empty string for root on purpose
	}}
	g.edges[GraphRootNodeID] = make(map[string]struct{})
	return g
}

// =============================================================================
// ADDING NODES AND EDGES
// =============================================================================

// AddArtifact adds an artifact node as a child of root.
func (g *SBOMGraph) AddArtifact(name string) string {
	id := "artifact:" + name
	if g.nodes[id] == nil {
		g.nodes[id] = &GraphNode{
			BOMRef: id,
			Type:   GraphNodeTypeArtifact,
			Component: &cdx.Component{
				BOMRef:     id,
				Name:       name,
				PackageURL: id,
				Type:       cdx.ComponentTypeApplication,
			},
		}
		g.edges[id] = make(map[string]struct{})
	}
	g.edges[GraphRootNodeID][id] = struct{}{}
	return id
}

// AddInfoSource adds an information source node as a child of an artifact.
// The info source ID is unique per artifact to prevent conflicts when merging graphs.
func (g *SBOMGraph) AddInfoSource(artifactID, sourceID string, sourceType InfoSourceType) string {
	// Extract artifact name from artifactID (e.g., "artifact:my-app" -> "my-app")
	_, artifactName := ParseGraphNodeID(artifactID)
	// Strip existing source type prefix to prevent double-prefixing (e.g., "sbom:sbom:url")
	if after, found := strings.CutPrefix(sourceID, string(sourceType)+":"); found {
		sourceID = after
	}
	// Create a unique ID that includes the artifact name
	id := fmt.Sprintf("%s:%s@%s", sourceType, sourceID, artifactName)
	if g.nodes[id] == nil {
		g.nodes[id] = &GraphNode{
			BOMRef:   id,
			Type:     GraphNodeTypeInfoSource,
			InfoType: sourceType,
			Component: &cdx.Component{
				BOMRef:     id,
				Name:       sourceID,
				PackageURL: id,
			},
		}
		g.edges[id] = make(map[string]struct{})
	}
	g.edges[artifactID][id] = struct{}{}
	return id
}

// isValidComponentType checks if a component type is valid per CycloneDX spec
func isValidComponentType(ct cdx.ComponentType) bool {
	validTypes := map[cdx.ComponentType]bool{
		cdx.ComponentTypeApplication:          true,
		cdx.ComponentTypeContainer:            true,
		cdx.ComponentTypeCryptographicAsset:   true,
		cdx.ComponentTypeData:                 true,
		cdx.ComponentTypeDevice:               true,
		cdx.ComponentTypeDeviceDriver:         true,
		cdx.ComponentTypeFile:                 true,
		cdx.ComponentTypeFirmware:             true,
		cdx.ComponentTypeFramework:            true,
		cdx.ComponentTypeLibrary:              true,
		cdx.ComponentTypeMachineLearningModel: true,
		cdx.ComponentTypeOS:                   true,
		cdx.ComponentTypePlatform:             true,
	}
	return validTypes[ct]
}

// sanitizeComponentType ensures the component type is valid, falling back to Library if not
func sanitizeComponentType(ct cdx.ComponentType) cdx.ComponentType {
	if isValidComponentType(ct) {
		return ct
	}
	// Fall back to Library for invalid types
	return cdx.ComponentTypeLibrary
}

// AddComponent adds a component node.
func (g *SBOMGraph) AddComponent(comp cdx.Component) string {
	if comp.PackageURL != "" {
		// Unescape URL-encoded characters (e.g., %2B -> +) to match the format stored in the database
		unescapedPurl, err := url.PathUnescape(comp.PackageURL)
		if err == nil {
			comp.PackageURL = unescapedPurl
		}
	}

	// Sanitize component type - fall back to Library if invalid
	comp.Type = sanitizeComponentType(comp.Type)

	if g.nodes[comp.BOMRef] == nil {
		g.nodes[comp.BOMRef] = &GraphNode{
			BOMRef:    comp.BOMRef,
			Type:      GraphNodeTypeComponent,
			Component: &comp,
		}
	}
	return comp.BOMRef
}

// AddEdge adds a directed edge from parent to child.
func (g *SBOMGraph) AddEdge(parentID, childID string) {
	if g.edges[parentID] == nil {
		g.edges[parentID] = make(map[string]struct{})
	}
	g.edges[parentID][childID] = struct{}{}
}

// statePriority returns a priority value for vulnerability states.
// Higher value = higher priority. exploitable > in_triage > false_positive
func statePriority(state cdx.ImpactAnalysisState) int {
	switch state {
	case cdx.IASExploitable:
		return 3
	case cdx.IASInTriage:
		return 2
	case cdx.IASFalsePositive:
		return 1
	default:
		return 0
	}
}

// AddVulnerability adds a vulnerability with deduplication.
// When the same CVE+Affects combination exists, state priority determines which one to keep:
// exploitable > in_triage > false_positive
func (g *SBOMGraph) AddVulnerability(vuln cdx.Vulnerability) {
	affectsStr := ""
	if vuln.Affects != nil {
		for _, aff := range *vuln.Affects {
			affectsStr += aff.Ref + ";"
		}
	}

	key := vuln.ID + "@" + affectsStr

	existing, exists := g.vulnerabilities[key]
	if !exists {
		g.vulnerabilities[key] = &vuln
		return
	}

	// Compare state priorities - higher priority wins
	existingState := cdx.ImpactAnalysisState("")
	if existing.Analysis != nil {
		existingState = existing.Analysis.State
	}

	newState := cdx.ImpactAnalysisState("")
	if vuln.Analysis != nil {
		newState = vuln.Analysis.State
	}

	if statePriority(newState) > statePriority(existingState) {
		g.vulnerabilities[key] = &vuln
	}
}

func (g *SBOMGraph) ClearScope() {
	g.scopeID = g.rootID
}

var ErrNodeNotReachable = fmt.Errorf("node not reachable from current scope")

func (g *SBOMGraph) Scope(id string) error {
	// check if valid
	if g.reachableNodes()[id] {
		g.scopeID = id
		return nil
	}
	return ErrNodeNotReachable
}

func (g *SBOMGraph) CurrentScopeID() string {
	return g.scopeID
}
func (g *SBOMGraph) ScopeToArtifact(artifactName string) error {
	artifactID := "artifact:" + artifactName
	return g.Scope(artifactID)
}

func (g *SBOMGraph) ScopeToInfoSource(infoSource string, t InfoSourceType) error {
	infoSourceID := fmt.Sprintf("%s:%s", t, infoSource) // info sources are uniquely identified by their name and type

	return g.Scope(infoSourceID)
}

func (g *SBOMGraph) IsScoped() bool {
	return g.scopeID != g.rootID
}

// Clone creates a deep copy of the graph.
func (g *SBOMGraph) Clone() *SBOMGraph {
	clone := &SBOMGraph{
		nodes:           make(map[string]*GraphNode, len(g.nodes)),
		edges:           make(map[string]map[string]struct{}, len(g.edges)),
		vulnerabilities: make(map[string]*cdx.Vulnerability, len(g.vulnerabilities)),
		rootID:          g.rootID,
		scopeID:         g.scopeID,
	}

	// Deep copy nodes
	for id, node := range g.nodes {
		clone.nodes[id] = &GraphNode{
			BOMRef:    node.BOMRef,
			Type:      node.Type,
			InfoType:  node.InfoType,
			Component: node.Component, // Note: Component is shared, make deep copy if needed
		}
	}

	// Deep copy edges
	for parentID, children := range g.edges {
		clone.edges[parentID] = make(map[string]struct{}, len(children))
		for childID := range children {
			clone.edges[parentID][childID] = struct{}{}
		}
	}

	// Deep copy vulnerabilities
	for id, vuln := range g.vulnerabilities {
		clone.vulnerabilities[id] = vuln // Note: Vuln is shared, make deep copy if needed
	}

	return clone
}

// GetInfoSourceNode returns the info source node by ID, or nil if not found.
func (g *SBOMGraph) GetInfoSourceNode(infoSourceID string) *GraphNode {
	if node := g.nodes[infoSourceID]; node != nil && node.Type == GraphNodeTypeInfoSource {
		return node
	}
	return nil
}

// HasInfoSource checks if an info source exists in the graph.
func (g *SBOMGraph) HasInfoSource(infoSourceID string) bool {
	return g.GetInfoSourceNode(infoSourceID) != nil
}

// MergeGraph merges another graph into this one, returning the diff.
// Artifacts from the other graph are added/merged under this graph's root.
// When an info source with the same ID exists, it replaces the entire subtree.
func (g *SBOMGraph) MergeGraph(other *SBOMGraph) GraphDiff {
	beforeNodes := g.reachableNodes()
	beforeEdges := make(map[[2]string]bool)
	for parent, child := range g.Edges() {
		beforeEdges[[2]string{parent, child}] = true
	}

	// Find info sources that need to be replaced (exist in both graphs)
	infoSourcesToReplace := make(map[string]bool)
	for id, node := range other.nodes {
		if node.Type == GraphNodeTypeInfoSource {
			if existingNode := g.nodes[id]; existingNode != nil && existingNode.Type == GraphNodeTypeInfoSource {
				infoSourcesToReplace[id] = true
			}
		}
	}

	// Remove old subtrees for info sources that will be replaced
	for infoSourceID := range infoSourcesToReplace {
		g.removeSubtree(infoSourceID)
	}

	// Import all nodes
	for bomRef, node := range other.nodes {
		if bomRef == GraphRootNodeID {
			continue // Skip root
		}
		// Always overwrite if node already exists (for replacement semantics)
		g.nodes[bomRef] = &GraphNode{
			BOMRef:    node.BOMRef,
			Type:      node.Type,
			InfoType:  node.InfoType,
			Component: node.Component,
		}
		if g.edges[bomRef] == nil {
			g.edges[bomRef] = make(map[string]struct{})
		}
	}

	// Import all edges
	for parentID, children := range other.edges {
		if parentID == GraphRootNodeID {
			// Connect root children to our root
			for childID := range children {
				g.edges[g.rootID][childID] = struct{}{}
			}
		} else {
			if g.edges[parentID] == nil {
				g.edges[parentID] = make(map[string]struct{})
			}
			// Clear existing edges for replaced info sources
			if infoSourcesToReplace[parentID] {
				g.edges[parentID] = make(map[string]struct{})
			}
			for childID := range children {
				g.edges[parentID][childID] = struct{}{}
			}
		}
	}

	// Calculate diff
	diff := GraphDiff{}
	afterNodes := g.reachableNodes()

	for id := range afterNodes {
		if !beforeNodes[id] {
			if node := g.nodes[id]; node != nil {
				diff.AddedNodes = append(diff.AddedNodes, node)
			}
		}
	}

	for parent, child := range g.Edges() {
		edge := [2]string{parent, child}
		if !beforeEdges[edge] {
			diff.AddedEdges = append(diff.AddedEdges, edge)
		}
	}
	// add vulnerabilities
	maps.Copy(g.vulnerabilities, other.vulnerabilities)
	return diff
}

// DeleteArtifactFromGraph removes an artifact and all its subtree from the graph.
// Returns a GraphDiff representing what was removed.
// DeleteArtifactFromGraph removes an artifact and all its subtree from the graph.
// Returns a GraphDiff representing what was removed.
// Only deletes nodes that are exclusively reachable through this artifact.
func (g *SBOMGraph) DeleteArtifactFromGraph(artifactName string) GraphDiff {
	artifactID := "artifact:" + artifactName

	beforeNodes := g.reachableNodes()
	beforeEdges := make(map[[2]string]bool)
	for parent, child := range g.Edges() {
		beforeEdges[[2]string{parent, child}] = true
	}

	// Check if artifact exists
	if g.nodes[artifactID] == nil {
		return GraphDiff{} // Nothing to delete
	}

	// Remove the edge from root to artifact (disconnect it)
	delete(g.edges[g.rootID], artifactID)

	// Now see what's still reachable - anything that became unreachable should be deleted
	stillReachable := g.reachableNodes()

	// Delete nodes that are no longer reachable
	for id := range beforeNodes {
		if !stillReachable[id] {
			delete(g.nodes, id)
			delete(g.edges, id)
		}
	}

	// Delete edges where either endpoint is no longer reachable
	for parentID, children := range g.edges {
		for childID := range children {
			if !stillReachable[parentID] || !stillReachable[childID] {
				delete(g.edges[parentID], childID)
			}
		}
	}

	// Calculate diff
	diff := GraphDiff{}
	afterNodes := g.reachableNodes()

	// Find removed nodes
	for id := range beforeNodes {
		if !afterNodes[id] {
			if node := g.nodes[id]; node != nil {
				diff.RemovedNodes = append(diff.RemovedNodes, node)
			}
		}
	}

	// Find removed edges
	for edge := range beforeEdges {
		found := false
		for parent, child := range g.Edges() {
			if [2]string{parent, child} == edge {
				found = true
				break
			}
		}
		if !found {
			diff.RemovedEdges = append(diff.RemovedEdges, edge)
		}
	}

	return diff
}

// GetArtifactIDs returns all artifact IDs in the graph.
func (g *SBOMGraph) GetArtifactIDs() []string {
	var ids []string
	for artifact := range g.Artifacts() {
		ids = append(ids, artifact.BOMRef)
	}
	return ids
}

// GetInfoSourceIDs returns all info source IDs for a given artifact.
func (g *SBOMGraph) GetInfoSourceIDs(artifactID string) []string {
	var ids []string
	for childID := range g.edges[artifactID] {
		if node := g.nodes[childID]; node != nil && node.Type == GraphNodeTypeInfoSource {
			ids = append(ids, childID)
		}
	}
	return ids
}

// GetParentIDs returns all parent node IDs for a given node.
func (g *SBOMGraph) GetParentIDs(nodeID string) []string {
	var parents []string
	for parentID, children := range g.edges {
		if _, hasChild := children[nodeID]; hasChild {
			parents = append(parents, parentID)
		}
	}
	return parents
}

// =============================================================================
// QUERIES
// =============================================================================

func (g *SBOMGraph) LicenseDistribution() map[string]int {
	licenseCount := make(map[string]int)
	for component := range g.Components() {
		if component.Component != nil {
			licenses := component.Component.Licenses
			if licenses != nil && len(*licenses) > 0 {
				for _, lic := range *licenses {
					if lic.License != nil && lic.License.ID != "" {
						licenseCount[lic.License.ID]++
					} else if lic.License != nil && lic.License.Name != "" {
						licenseCount[lic.License.Name]++
					} else if lic.Expression != "" {
						licenseCount[lic.Expression]++
					}
				}
			}
		}
	}
	return licenseCount
}

// Node returns a node by ID, or nil if not reachable from scope.
func (g *SBOMGraph) Node(id string) *GraphNode {
	if !g.isReachable(id) {
		return nil
	}
	return g.nodes[id]
}

// Children returns an iterator over direct children of a node.
func (g *SBOMGraph) Children(nodeID string) iter.Seq[*GraphNode] {
	return func(yield func(*GraphNode) bool) {
		for childID := range g.edges[nodeID] {
			if node := g.nodes[childID]; node != nil {
				if !yield(node) {
					return
				}
			}
		}
	}
}

// ChildrenOfType returns children of a specific type.
func (g *SBOMGraph) ChildrenOfType(nodeID string, nodeType GraphNodeType) iter.Seq[*GraphNode] {
	return func(yield func(*GraphNode) bool) {
		for child := range g.Children(nodeID) {
			if child.Type == nodeType {
				if !yield(child) {
					return
				}
			}
		}
	}
}

// NodesOfType returns all reachable nodes of a specific type.
func (g *SBOMGraph) NodesOfType(nodeType GraphNodeType) iter.Seq[*GraphNode] {
	return func(yield func(*GraphNode) bool) {
		visited := make(map[string]bool)
		var visit func(id string) bool
		visit = func(id string) bool {
			if visited[id] {
				return true
			}
			visited[id] = true

			if node := g.nodes[id]; node != nil && node.Type == nodeType {
				if !yield(node) {
					return false
				}
			}

			for _, childID := range slices.Sorted(maps.Keys(g.edges[id])) {
				if !visit(childID) {
					return false
				}
			}
			return true
		}
		visit(g.scopeID)
	}
}

func BomIsSBOM(bom *cdx.BOM) bool {
	if bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) > 0 {
		return false
	}
	return true
}

// Components returns all component nodes reachable from scope.
func (g *SBOMGraph) Components() iter.Seq[*GraphNode] {
	return g.NodesOfType(GraphNodeTypeComponent)
}

// Artifacts returns all artifact nodes reachable from scope.
func (g *SBOMGraph) Artifacts() iter.Seq[*GraphNode] {
	return g.NodesOfType(GraphNodeTypeArtifact)
}

// InfoSources returns all information source nodes reachable from scope.
func (g *SBOMGraph) InfoSources() iter.Seq[*GraphNode] {
	return g.NodesOfType(GraphNodeTypeInfoSource)
}

// Edges returns all edges where both endpoints are reachable from scope.
func (g *SBOMGraph) Edges() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		reachable := g.reachableNodes()
		for parent, children := range g.edges {
			if !reachable[parent] {
				continue
			}
			for child := range children {
				if !reachable[child] {
					continue
				}
				if !yield(parent, child) {
					return
				}
			}
		}
	}
}

// ComponentEdges returns edges between components only.
func (g *SBOMGraph) ComponentEdges() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for parent, child := range g.Edges() {
			pNode := g.nodes[parent]
			cNode := g.nodes[child]
			if pNode != nil && cNode != nil && pNode.Type == GraphNodeTypeComponent && cNode.Type == GraphNodeTypeComponent {
				if !yield(parent, child) {
					return
				}
			}
		}
	}
}

// Vulnerabilities returns all vulnerabilities.
// Deduplication with state priority is handled in AddVulnerability.
func (g *SBOMGraph) Vulnerabilities() iter.Seq[*cdx.Vulnerability] {
	return func(yield func(*cdx.Vulnerability) bool) {
		for _, v := range g.vulnerabilities {
			if !yield(v) {
				return
			}
		}
	}
}

// =============================================================================
// ANALYSIS
// =============================================================================

// CountInfoSourcesPerComponent returns how many info sources each component appears under.
// Key insight: traverse from each info source and count how many times each component is reached.
func (g *SBOMGraph) CountInfoSourcesPerComponent() map[string]map[InfoSourceType]int {
	result := make(map[string]map[InfoSourceType]int)

	for infoSource := range g.InfoSources() {
		visited := make(map[string]bool)
		var visit func(id string)
		visit = func(id string) {
			if visited[id] {
				return
			}
			visited[id] = true

			node := g.nodes[id]
			if node != nil && node.Type == GraphNodeTypeComponent {
				if result[id] == nil {
					result[id] = make(map[InfoSourceType]int)
				}
				result[id][infoSource.InfoType]++
			}

			for childID := range g.edges[id] {
				visit(childID)
			}
		}
		visit(infoSource.BOMRef)
	}

	return result
}

// ComponentsWithMultipleSources returns component IDs that appear in multiple SBOMs or have VEX/CSAF.
// These cannot be automatically marked as "fixed".
func (g *SBOMGraph) ComponentsWithMultipleSources() []string {
	// we need to reset the scope
	oldScope := g.CurrentScopeID()
	g.ClearScope()

	counts := g.CountInfoSourcesPerComponent()
	var result []string

	for id, typeCounts := range counts {
		if typeCounts[InfoSourceSBOM] > 1 {
			result = append(result, id)
		}
	}
	err := g.Scope(oldScope)
	if err != nil {
		panic("failed to restore scope after counting info sources: " + err.Error())
	}

	return result
}

func (g *SBOMGraph) FindAllComponentOnlyPathsToPURL(purl string, limit int) []Path {
	// Find the target node ID
	var targetID string
	for node := range g.Components() {
		if node.Component != nil && strings.EqualFold(node.Component.PackageURL, purl) {
			targetID = node.BOMRef
			break
		}
	}

	if targetID == "" {
		return nil
	}

	// Build reverse edge map (child -> parents) for backward traversal
	// Sort parent IDs for deterministic traversal order
	reverseEdges := make(map[string][]string)
	for parent, children := range g.edges {
		for child := range children {
			reverseEdges[child] = append(reverseEdges[child], parent)
		}
	}
	// Sort each parent list for deterministic order
	for child := range reverseEdges {
		slices.Sort(reverseEdges[child])
	}

	// Use BFS to find paths in order of increasing length
	// This allows us to stop early once we have enough paths
	var paths []Path
	seen := make(map[string]bool) // For path deduplication

	// Queue holds partial paths (stored in reverse: target first, growing toward root)
	type queueItem struct {
		path   []string
		onPath map[string]bool // Track nodes in current path to detect cycles
	}
	queue := []queueItem{{
		path:   []string{targetID},
		onPath: map[string]bool{targetID: true},
	}}

	for len(queue) > 0 {
		// Check if we've reached the limit
		if limit > 0 && len(paths) >= limit {
			break
		}

		current := queue[0]
		queue = queue[1:]

		lastNode := current.path[len(current.path)-1]

		// Get parents of the last node
		parents := reverseEdges[lastNode]
		foundTermination := false

		for _, parentID := range parents {
			// Cycle detection
			if current.onPath[parentID] {
				continue
			}

			// Check if parent is NOT a component (termination condition)
			// Use node type from graph instead of ID format, because BOMRef
			// may not be a PURL even though the component has a valid PackageURL.
			parentNode := g.nodes[parentID]
			if parentNode == nil || parentNode.Type != GraphNodeTypeComponent {
				foundTermination = true
				// Build path in correct order (root to target)
				result := make([]string, len(current.path))
				for i, j := 0, len(current.path)-1; j >= 0; i, j = i+1, j-1 {
					result[i] = current.path[j]
				}
				key := strings.Join(result, "|")
				if !seen[key] {
					seen[key] = true
					paths = append(paths, Path(result))
					// Check limit after adding
					if limit > 0 && len(paths) >= limit {
						break
					}
				}
			}
		}

		// If we reached limit, stop processing
		if limit > 0 && len(paths) >= limit {
			break
		}

		// If no termination found, continue extending path through component parents
		if !foundTermination || len(parents) > 0 {
			for _, parentID := range parents {
				if current.onPath[parentID] {
					continue
				}
				pNode := g.nodes[parentID]
				if pNode == nil || pNode.Type != GraphNodeTypeComponent {
					continue // Skip non-components for path extension
				}
				// Extend path
				newPath := make([]string, len(current.path)+1)
				copy(newPath, current.path)
				newPath[len(current.path)] = parentID
				newOnPath := make(map[string]bool, len(current.onPath)+1)
				maps.Copy(newOnPath, current.onPath)
				newOnPath[parentID] = true
				queue = append(queue, queueItem{path: newPath, onPath: newOnPath})
			}
		}
	}
	// translate each path and path entry to the package purl of that component
	for i, path := range paths {
		for j, nodeID := range path {
			node := g.nodes[nodeID]
			if node != nil && node.Component != nil && node.Component.PackageURL != "" {
				paths[i][j] = node.Component.PackageURL
			}
		}
	}

	return paths
}

// =============================================================================
// DIFF
// =============================================================================

// GraphDiff represents differences between two graph states.
type GraphDiff struct {
	AddedNodes   []*GraphNode // nodes added
	RemovedNodes []*GraphNode // nodes removed
	AddedEdges   [][2]string  // edges added [parent, child] - ROOT will be replaced by nil so that it matches the db schema
	RemovedEdges [][2]string  // edges removed [parent, child] - ROOT will be replaced by nil so that it matches the db schema
}

// IsEmpty returns true if there are no changes.
func (d GraphDiff) IsEmpty() bool {
	return len(d.AddedNodes) == 0 && len(d.RemovedNodes) == 0 &&
		len(d.AddedEdges) == 0 && len(d.RemovedEdges) == 0
}

// AddedNodeIDs returns just the IDs of added nodes.
func (d GraphDiff) AddedNodeIDs() []string {
	ids := make([]string, len(d.AddedNodes))
	for i, n := range d.AddedNodes {
		ids[i] = n.BOMRef
	}
	return ids
}

// RemovedNodeIDs returns just the IDs of removed nodes.
func (d GraphDiff) RemovedNodeIDs() []string {
	ids := make([]string, len(d.RemovedNodes))
	for i, n := range d.RemovedNodes {
		ids[i] = n.BOMRef
	}
	return ids
}

type BOMMetadata struct {
	AssetVersionSlug      string
	AssetSlug             string
	OrgSlug               string
	ProjectSlug           string
	FrontendURL           string
	ArtifactName          string
	AssetID               uuid.UUID
	AddExternalReferences bool
	RootName              string // defaults to ArtifactName if empty
	AssetVersionName      string
}

// =============================================================================
// EXPORT
// =============================================================================

type minimalTree struct {
	Nodes        []string            `json:"nodes"`
	Dependencies map[string][]string `json:"dependencies"`
}

func (g *SBOMGraph) ToMinimalTree() minimalTree {
	reachable := g.reachableNodes()
	nodes := make([]string, 0, len(reachable))
	dependencies := make(map[string][]string)
	depMap := edgesToDepMap(g.edges)

	// Only add nodes that are reachable in current scope
	for id := range reachable {
		node := g.nodes[id]
		if node != nil && node.Component != nil {
			nodes = append(nodes, node.Component.PackageURL)
		}
	}

	// add the ROOT node PackageURL (which is an empty string to the nodes list to ensure it's included in the minimal tree)
	nodes = append(nodes, "")

	for parent := range g.edges {
		if !reachable[parent] {
			continue
		}
		parentNode := g.nodes[parent]
		if parentNode == nil {
			continue
		}
		parentPURL := parentNode.Component.PackageURL

		children := getChildrenOfParent(depMap, g.nodes, parent)
		deps := make([]string, 0, len(children))
		for _, child := range children {
			if !reachable[child] {
				continue
			}
			childNode := g.nodes[child]
			if childNode == nil {
				continue
			}
			childPURL := childNode.Component.PackageURL
			deps = append(deps, childPURL)
		}
		dependencies[parentPURL] = deps
	}
	return minimalTree{
		Nodes:        nodes,
		Dependencies: dependencies,
	}
}

// MinimalTreeToPURL returns a minimal tree structure containing only the subgraph
// of nodes that lead to the specified PURL. This collects all ancestor nodes
// without enumerating individual paths, avoiding combinatorial explosion.
// The maxDepth parameter limits how far back we traverse (0 = unlimited).
func (g *SBOMGraph) MinimalTreeToPURL(purl string, maxDepth int) minimalTree {
	// Find the target node ID
	var targetID string
	for node := range g.Components() {
		if node.Component != nil && strings.EqualFold(node.Component.PackageURL, purl) {
			targetID = node.BOMRef
			break
		}
	}

	if targetID == "" {
		return minimalTree{Nodes: []string{}, Dependencies: map[string][]string{}}
	}

	// Build reverse edge map (child -> parents)
	reverseEdges := make(map[string][]string)
	for parent, children := range g.edges {
		for child := range children {
			reverseEdges[child] = append(reverseEdges[child], parent)
		}
	}

	// BFS backward from target to collect all ancestor nodes and edges
	// We collect the subgraph, not individual paths - O(V+E) instead of O(paths)
	visited := make(map[string]bool)
	dependencies := make(map[string][]string)

	type queueItem struct {
		nodeID string
		depth  int
	}
	queue := []queueItem{{nodeID: targetID, depth: 0}}
	visited[targetID] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Check depth limit
		if maxDepth > 0 && current.depth >= maxDepth {
			continue
		}

		// Process all parents of current node
		for _, parentID := range reverseEdges[current.nodeID] {
			// Only follow component edges for the tree structure
			// Use node type from graph instead of ID format, because BOMRef
			// may not be a PURL even though the component has a valid PackageURL.
			pNode := g.nodes[parentID]
			if pNode == nil || pNode.Type != GraphNodeTypeComponent {
				continue
			}

			// Record the edge (parent -> child)
			deps := dependencies[parentID]
			found := false
			for _, d := range deps {
				if d == current.nodeID {
					found = true
					break
				}
			}
			if !found {
				dependencies[parentID] = append(dependencies[parentID], current.nodeID)
			}

			// Visit parent if not already visited
			if !visited[parentID] {
				visited[parentID] = true
				queue = append(queue, queueItem{nodeID: parentID, depth: current.depth + 1})
			}
		}
	}

	// Convert visited set to sorted slice
	nodes := make([]string, 0, len(visited))
	for node := range visited {
		nodes = append(nodes, node)
	}
	slices.Sort(nodes)

	// Sort dependencies for deterministic output
	for k := range dependencies {
		slices.Sort(dependencies[k])
	}

	return minimalTree{
		Nodes:        nodes,
		Dependencies: dependencies,
	}
}

// ToCycloneDX exports the scoped view as a CycloneDX BOM.
func (g *SBOMGraph) ToCycloneDX(metadata BOMMetadata) *cdx.BOM {
	var externalRefs *[]cdx.ExternalReference
	if metadata.AddExternalReferences {
		apiURL := os.Getenv("API_URL")
		// Use QueryEscape to encode all special characters including colons
		// PathEscape is too lenient for artifact names which may contain PURLs or other special chars
		escapedArtifactName := url.QueryEscape(metadata.ArtifactName)

		vexURL := fmt.Sprintf("%s/api/v1/public/%s/refs/%s/artifacts/%s/vex.json/", apiURL, metadata.AssetID.String(), metadata.AssetVersionSlug, escapedArtifactName)
		sbomURL := fmt.Sprintf("%s/api/v1/public/%s/refs/%s/artifacts/%s/sbom.json/", apiURL, metadata.AssetID.String(), metadata.AssetVersionSlug, escapedArtifactName)

		dashboardURL := getDashboardURL(metadata)

		externalRefs = &[]cdx.ExternalReference{{
			URL:     vexURL,
			Comment: "Up to date Vulnerability exploitability information.",
			Type:    cdx.ERTypeExploitabilityStatement,
		}, {
			URL:     sbomURL,
			Comment: "Software bill of materials.",
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

	rootName := metadata.RootName
	if rootName == "" {
		// If ArtifactName is a valid PURL, parse it and set the version properly
		// so that the version appears before qualifiers (e.g. pkg:oci/name@version?qualifier=value)
		if p, err := packageurl.FromString(metadata.ArtifactName); err == nil && metadata.AssetVersionName != "" {
			p.Version = metadata.AssetVersionName
			rootName = p.String()
		} else {
			rootName = fmt.Sprintf("%s@%s", metadata.ArtifactName, metadata.AssetVersionName)
		}
	}

	// check if valid purl
	p, err := packageurl.FromString(rootName)
	pURL := ""
	if err == nil {
		pURL = p.String()
	}

	components := []cdx.Component{}
	for node := range g.Components() {
		if node.Component != nil {
			components = append(components, *node.Component)
		}
	}

	// we always need to add the root component
	rootComponent := cdx.Component{
		BOMRef:     rootName,
		Name:       rootName,
		Type:       cdx.ComponentTypeApplication,
		PackageURL: pURL,
	}
	components = append(components, rootComponent)

	// Build dependency map: component -> its component children
	depMap := make(map[string][]string)
	depMap[rootName] = []string{}

	// componentEdges wont return the root's direct deps, so we add them later
	for parent, child := range g.ComponentEdges() {
		// check if child is already in depMap
		if slices.Contains(depMap[parent], child) {
			continue
		}
		depMap[parent] = append(depMap[parent], child)
	}

	// Root's direct deps are the first-level components (children of info sources)
	for infoSource := range g.InfoSources() {
		for childID := range g.edges[infoSource.BOMRef] {
			if node := g.nodes[childID]; node != nil && node.Type == GraphNodeTypeComponent {
				if slices.Contains(depMap[rootName], childID) {
					continue
				}
				depMap[rootName] = append(depMap[rootName], childID)
			}
		}
	}

	dependencies := []cdx.Dependency{}
	for c := range g.Components() {
		deps := depMap[c.BOMRef]
		if deps == nil {
			deps = []string{} // Ensure empty array, not null in JSON
		}
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          c.Component.BOMRef,
			Dependencies: &deps,
		})
	}

	// include the depMap entries for root
	rootDeps := depMap[rootName]
	if rootDeps == nil {
		rootDeps = []string{} // Ensure empty array, not null in JSON
	}
	dependencies = append(dependencies, cdx.Dependency{
		Ref:          rootName,
		Dependencies: &rootDeps,
	})

	vulns := []cdx.Vulnerability{}
	for v := range g.Vulnerabilities() {
		vulns = append(vulns, *v)
	}

	return &cdx.BOM{
		SpecVersion: cdx.SpecVersion1_6,
		BOMFormat:   "CycloneDX",
		Version:     1,
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef:     rootName,
				Name:       rootName,
				Type:       cdx.ComponentTypeApplication,
				PackageURL: pURL,
			},
		},
		Components:         &components,
		Dependencies:       &dependencies,
		Vulnerabilities:    &vulns,
		ExternalReferences: externalRefs,
	}
}

func RemoveInformationSourcePrefixIfExists(origin string) (InfoSourceType, string) {
	if after, ok := strings.CutPrefix(origin, fmt.Sprintf("%s:", InfoSourceSBOM)); ok {
		return InfoSourceSBOM, after
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

// =============================================================================
// INTERNAL
// =============================================================================

func (g *SBOMGraph) reachableNodes() map[string]bool {
	reachable := make(map[string]bool)
	var visit func(id string)
	visit = func(id string) {
		if reachable[id] {
			return
		}
		reachable[id] = true
		for childID := range g.edges[id] {
			visit(childID)
		}
	}
	visit(g.scopeID)
	return reachable
}

// removeSubtree removes all nodes and edges in the subtree rooted at the given node.
// The node itself is kept but its children are removed.
func (g *SBOMGraph) removeSubtree(rootID string) {
	// Find all nodes in the subtree (but not the root itself)
	nodesToRemove := make(map[string]bool)
	var visit func(id string)
	visit = func(id string) {
		for childID := range g.edges[id] {
			if !nodesToRemove[childID] {
				nodesToRemove[childID] = true
				visit(childID)
			}
		}
	}
	visit(rootID)

	// Remove the nodes and their edges
	for nodeID := range nodesToRemove {
		delete(g.nodes, nodeID)
		delete(g.edges, nodeID)

		// Remove any edges pointing to this node
		for parentID := range g.edges {
			delete(g.edges[parentID], nodeID)
		}
	}

	// Clear the root node's children edges
	g.edges[rootID] = make(map[string]struct{})
}

func (g *SBOMGraph) isReachable(id string) bool {
	return g.reachableNodes()[id]
}

func getDashboardURL(metadata BOMMetadata) string {
	dashboardURL := ""
	if metadata.FrontendURL != "" && metadata.OrgSlug != "" && metadata.ProjectSlug != "" && metadata.AssetSlug != "" {
		dashboardURL = fmt.Sprintf("%s/%s/projects/%s/assets/%s", metadata.FrontendURL, metadata.OrgSlug, metadata.ProjectSlug, metadata.AssetSlug)
	}

	if dashboardURL != "" {
		dashboardURL = fmt.Sprintf("%s/refs/main", dashboardURL)
	}

	return dashboardURL
}

// =============================================================================
// PARSING FROM CYCLONEDX
// =============================================================================

// SBOMGraphFromCycloneDX creates an SBOMGraph from a CycloneDX BOM.
func SBOMGraphFromCycloneDX(bom *cdx.BOM, artifactName, infoSourceID string, keepOriginalSbomRootComponent bool) (*SBOMGraph, error) {
	// Validate required fields
	if bom == nil {
		return nil, fmt.Errorf("BOM cannot be nil")
	}

	// Validate metadata and root component exist
	if bom.Metadata == nil {
		return nil, fmt.Errorf("BOM metadata is required")
	}
	if bom.Metadata.Component == nil {
		return nil, fmt.Errorf("metadata component is required")
	}

	rootComponent := bom.Metadata.Component

	// Validate root component required fields
	if rootComponent.BOMRef == "" {
		return nil, fmt.Errorf("root component BOMRef is required")
	}
	if rootComponent.Name == "" {
		return nil, fmt.Errorf("root component name is required")
	}

	// if we want to keep the original root component, we need to validate that it has a valid purl, otherwise we will not be able to add it to the graph
	if keepOriginalSbomRootComponent {
		if rootComponent.PackageURL == "" {
			return nil, fmt.Errorf("root component PackageURL is required when keepOriginalSbomRootComponent is true")
		}
		if _, err := packageurl.FromString(rootComponent.PackageURL); err != nil {
			return nil, fmt.Errorf("root component has invalid PackageURL: %w", err)
		}
	}

	// Validate BOM format
	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("invalid BOM format: %s (expected CycloneDX)", bom.BOMFormat)
	}

	// Validate BOM version
	if bom.SpecVersion < 1 {
		return nil, fmt.Errorf("BOM spec version must be >= 1, got %d", bom.SpecVersion)
	}

	g := NewSBOMGraph()

	artifactID := g.AddArtifact(artifactName)
	infoID := g.AddInfoSource(artifactID, infoSourceID, InfoSourceSBOM)

	// Add root component
	if err := g.validateAndAddComponent(*rootComponent); err != nil {
		return nil, fmt.Errorf("invalid root component: %w", err)
	}

	// Track BOMRefs to detect duplicates
	seenBOMRefs := make(map[string]bool)
	// Process regular components
	if bom.Components != nil {
		for idx, comp := range *bom.Components {
			// Validate required fields
			if comp.BOMRef == "" {
				return nil, fmt.Errorf("component at index %d has missing BOMRef", idx)
			}
			if comp.Name == "" {
				return nil, fmt.Errorf("component at index %d (%s) has missing Name", idx, comp.BOMRef)
			}

			// Check for duplicate BOMRef
			if seenBOMRefs[comp.BOMRef] {
				slog.Warn("duplicate BOMRef found, skipping component", "bomRef", comp.BOMRef)
				continue
			}
			seenBOMRefs[comp.BOMRef] = true

			// Validate PackageURL format if present
			if comp.PackageURL != "" {
				if _, err := packageurl.FromString(comp.PackageURL); err != nil {
					return nil, fmt.Errorf("component %s has invalid PackageURL: %w", comp.BOMRef, err)
				}
			}

			// Validate scope if set
			if comp.Scope != "" {
				validScopes := map[cdx.Scope]bool{
					cdx.ScopeExcluded: true,
					cdx.ScopeOptional: true,
					cdx.ScopeRequired: true,
				}
				if !validScopes[comp.Scope] {
					return nil, fmt.Errorf("component %s has invalid scope: %s", comp.BOMRef, comp.Scope)
				}
			}

			// Sanitize invalid hashes (remove them instead of erroring)
			if comp.Hashes != nil {
				validHashes := []cdx.Hash{}
				for _, hash := range *comp.Hashes {
					if isValidHashAlgorithm(hash.Algorithm) {
						validHashes = append(validHashes, hash)
					}
					// Invalid hashes are silently dropped
				}
				if len(validHashes) > 0 {
					comp.Hashes = &validHashes
				} else {
					comp.Hashes = nil
				}
			}

			// Sanitize external references (remove invalid types)
			if comp.ExternalReferences != nil {
				validRefs := []cdx.ExternalReference{}
				for _, ref := range *comp.ExternalReferences {
					if isValidExternalReferenceType(ref.Type) {
						validRefs = append(validRefs, ref)
					}
					// Invalid references are silently dropped
				}
				if len(validRefs) > 0 {
					comp.ExternalReferences = &validRefs
				} else {
					comp.ExternalReferences = nil
				}
			}

			// Add component (type sanitization already happens in AddComponent)
			if looksLikePackagePURL(comp.PackageURL) {
				g.AddComponent(comp)
			}
		}
	}

	// Validate and build dependency map
	depMap := make(map[string][]string)
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies != nil {
				// Validate that referenced components exist
				for _, childRef := range *dep.Dependencies {
					if childRef != "" && childRef != rootComponent.BOMRef && !seenBOMRefs[childRef] {
						return nil, fmt.Errorf("dependency references undefined component: %s", childRef)
					}
				}
				depMap[dep.Ref] = *dep.Dependencies
			}
		}
	}

	rootRef := rootComponent.BOMRef

	// Add edges
	for parent := range depMap {
		parentNode := g.nodes[parent]
		// skip if parent is not a component or info source
		if parentNode == nil {
			continue
		}

		if parentNode.Type != GraphNodeTypeComponent && parentNode.BOMRef != rootRef {
			// not a valid parent
			continue
		}
		// If parent is root or a root project component, add children as info source children
		children := getChildrenOfParent(depMap, g.nodes, parent)
		edgeSource := parent
		if parent == rootRef && !keepOriginalSbomRootComponent {
			edgeSource = infoID
		}
		for _, child := range children {
			g.AddEdge(edgeSource, child)
		}
	}

	// If no explicit root dependencies, all components are roots
	if len(depMap[rootRef]) == 0 {
		if bom.Components != nil {
			for _, comp := range *bom.Components {
				if !looksLikePackagePURL(comp.PackageURL) {
					continue // Skip root project components
				}
				// Check if this component is a child of any other
				isChild := false
				for _, children := range depMap {
					if slices.Contains(children, comp.BOMRef) {
						isChild = true
						break
					}
				}
				if !isChild {
					g.AddEdge(infoID, comp.BOMRef) // link to info source
				}
			}
		}
	}

	// If keepOriginalSbomRootComponent is true, add edge from infosource to original root ref
	if keepOriginalSbomRootComponent && rootRef != "" {
		g.AddEdge(infoID, rootRef)
	}

	// Add vulnerabilities (ignore invalid severity values)
	if bom.Vulnerabilities != nil {
		for _, vuln := range *bom.Vulnerabilities {
			// Sanitize invalid severity values in ratings
			if vuln.Ratings != nil {
				validRatings := []cdx.VulnerabilityRating{}
				for _, rating := range *vuln.Ratings {
					if isValidSeverity(rating.Severity) {
						validRatings = append(validRatings, rating)
					}
					// Invalid ratings are silently dropped
				}
				if len(validRatings) > 0 {
					vuln.Ratings = &validRatings
				} else {
					vuln.Ratings = nil
				}
			}
			g.AddVulnerability(vuln)
		}
	}

	return g, nil
}

// validateAndAddComponent validates a component before adding it
func (g *SBOMGraph) validateAndAddComponent(comp cdx.Component) error {
	if comp.BOMRef == "" {
		return fmt.Errorf("component BOMRef is required")
	}
	if comp.Name == "" {
		return fmt.Errorf("component Name is required")
	}
	if comp.PackageURL != "" {
		if _, err := packageurl.FromString(comp.PackageURL); err != nil {
			return fmt.Errorf("invalid PackageURL: %w", err)
		}
	}
	g.AddComponent(comp)
	return nil
}

// isValidHashAlgorithm checks if hash algorithm is valid
func isValidHashAlgorithm(alg cdx.HashAlgorithm) bool {
	validAlgos := map[cdx.HashAlgorithm]bool{
		cdx.HashAlgoMD5:         true,
		cdx.HashAlgoSHA1:        true,
		cdx.HashAlgoSHA256:      true,
		cdx.HashAlgoSHA384:      true,
		cdx.HashAlgoSHA512:      true,
		cdx.HashAlgoSHA3_256:    true,
		cdx.HashAlgoSHA3_384:    true,
		cdx.HashAlgoSHA3_512:    true,
		cdx.HashAlgoBlake2b_256: true,
		cdx.HashAlgoBlake2b_384: true,
		cdx.HashAlgoBlake2b_512: true,
		cdx.HashAlgoBlake3:      true,
	}
	return validAlgos[alg]
}

// isValidExternalReferenceType checks if external reference type is valid
func isValidExternalReferenceType(t cdx.ExternalReferenceType) bool {
	validTypes := map[cdx.ExternalReferenceType]bool{
		cdx.ERTypeAdversaryModel:          true,
		cdx.ERTypeAdvisories:              true,
		cdx.ERTypeAttestation:             true,
		cdx.ERTypeBOM:                     true,
		cdx.ERTypeBuildMeta:               true,
		cdx.ERTypeBuildSystem:             true,
		cdx.ERTypeCertificationReport:     true,
		cdx.ERTypeChat:                    true,
		cdx.ERTypeConfiguration:           true,
		cdx.ERTypeCodifiedInfrastructure:  true,
		cdx.ERTypeComponentAnalysisReport: true,
		cdx.ERTypeDistribution:            true,
		cdx.ERTypeDistributionIntake:      true,
		cdx.ERTypeDocumentation:           true,
		cdx.ERTypeDynamicAnalysisReport:   true,
		cdx.ERTypeEvidence:                true,
		cdx.ERTypeExploitabilityStatement: true,
		cdx.ERTypeFormulation:             true,
		cdx.ERTypeIssueTracker:            true,
		cdx.ERTypeLicense:                 true,
	}
	return validTypes[t]
}

// isValidSeverity checks if severity is valid
func isValidSeverity(severity cdx.Severity) bool {
	validSeverities := map[cdx.Severity]bool{
		cdx.SeverityUnknown:  true,
		cdx.SeverityLow:      true,
		cdx.SeverityMedium:   true,
		cdx.SeverityHigh:     true,
		cdx.SeverityCritical: true,
		cdx.SeverityInfo:     true,
		cdx.SeverityNone:     true,
	}
	return validSeverities[severity]
}

func getChildrenOfParent(depMap map[string][]string, nodes map[string]*GraphNode, parent string) []string {
	// imagine a tree which contains the following edges:
	// ROOT -> fake node -> pkg:a -> pkg:b
	// this function should return only pkg:a when parent is ROOT
	children, exists := depMap[parent]
	if !exists {
		return []string{}
	}
	// check if any of the children are fake nodes (not starting with pkg:)
	realChildren := make([]string, 0, len(children))
	for _, child := range children {
		childNode := nodes[child]
		if childNode == nil {
			// Node not in graph - could be a fake node, recurse to find its real children
			realChildren = append(realChildren, getChildrenOfParent(depMap, nodes, child)...)
			continue
		}
		if childNode.Type == GraphNodeTypeComponent {
			realChildren = append(realChildren, child)
		} else {
			// we need to get the children of this fake node instead
			realChildren = append(realChildren, getChildrenOfParent(depMap, nodes, child)...)
		}
	}
	return realChildren
}

func SBOMGraphFromVulnerabilities(vulns []cdx.Vulnerability) *SBOMGraph {
	g := NewSBOMGraph()

	// Create artifact and info source to connect components to the graph
	artifactID := g.AddArtifact("vex")
	infoSourceID := g.AddInfoSource(artifactID, "vex", InfoSourceSBOM)

	for _, vuln := range vulns {
		g.AddVulnerability(vuln)

		// Extract affected components and add them to the graph
		if vuln.Affects != nil {
			for _, aff := range *vuln.Affects {
				purlStr := aff.Ref
				if purlStr == "" {
					continue
				}

				// Parse the PURL to extract name and version
				purl, err := packageurl.FromString(purlStr)
				if err != nil {
					continue
				}

				comp := cdx.Component{
					BOMRef:     purlStr,
					Name:       purl.Name,
					Version:    purl.Version,
					PackageURL: purlStr,
					Type:       cdx.ComponentTypeLibrary,
				}
				compID := g.AddComponent(comp)
				g.AddEdge(infoSourceID, compID)
			}
		}
	}
	return g
}

func looksLikePackagePURL(id string) bool {
	return strings.HasPrefix(id, "pkg:") && strings.Contains(id, "@")
}

// =============================================================================
// UTILITY
// =============================================================================

// ParseGraphNodeID extracts the type prefix and name from a node ID.
// e.g., "artifact:my-app" -> ("artifact", "my-app")
func ParseGraphNodeID(id string) (prefix, name string) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", id
}

// =============================================================================
// COMPONENT INTERFACE FOR DATABASE LOADING
// =============================================================================

// GraphComponent represents a component that can be loaded from the database.
type GraphComponent interface {
	GetID() string
	GetDependentID() *string
	ToCdxComponent(componentLicenseOverwrites map[string]string) (cdx.Component, error)
}

// SBOMGraphFromComponents builds an SBOMGraph from database components.
// The components include artifact nodes, information source nodes, and regular components.
// This function reconstructs the full graph structure from the flat component list.
// Uses generics to avoid slice type conversion and reduce memory allocations.
func SBOMGraphFromComponents[T GraphComponent](components []T, licenseOverwrites map[string]string) (*SBOMGraph, error) {
	g := NewSBOMGraph()

	// Build dependency map: parent -> children
	dependencyMap := make(map[string][]string, len(components))
	for _, c := range components {
		var parentID string
		if c.GetDependentID() != nil {
			parentID = *c.GetDependentID()
		} else {
			parentID = GraphRootNodeID
		}
		dependencyMap[parentID] = append(dependencyMap[parentID], c.GetID())
	}

	// First pass: create all nodes
	processedComponents := make(map[string]struct{}, len(components))
	for _, comp := range components {
		id := comp.GetID()
		if _, alreadyProcessed := processedComponents[id]; alreadyProcessed {
			continue
		}
		processedComponents[id] = struct{}{}

		cdxComp, err := comp.ToCdxComponent(licenseOverwrites)
		if err != nil {
			continue
		}

		// Determine node type from ID prefix
		prefix, name := ParseGraphNodeID(id)
		switch prefix {
		case "artifact":
			g.nodes[id] = &GraphNode{
				BOMRef: id,
				Type:   GraphNodeTypeArtifact,
				Component: &cdx.Component{
					BOMRef: id,
					Name:   name,
					Type:   cdx.ComponentTypeApplication,
				},
			}
			g.edges[id] = make(map[string]struct{})
		case string(InfoSourceSBOM):
			g.nodes[id] = &GraphNode{
				BOMRef:    id,
				Type:      GraphNodeTypeInfoSource,
				InfoType:  InfoSourceType(prefix),
				Component: &cdxComp,
			}
			g.edges[id] = make(map[string]struct{})
		default:
			// Regular component
			g.nodes[id] = &GraphNode{
				BOMRef:    id,
				Type:      GraphNodeTypeComponent,
				Component: &cdxComp,
			}
			g.edges[id] = make(map[string]struct{})
		}
	}

	// Second pass: create edges
	for parentID, children := range dependencyMap {
		for _, childID := range children {
			if g.nodes[childID] != nil {
				g.AddEdge(parentID, childID)
			}
		}
	}

	return g, nil
}

// NodeIDsAndEdges returns a flat representation of the graph for comparison.
type FlatGraph struct {
	Nodes []string
	Edges [][2]string
}

// NodeIDsAndEdges returns all node IDs and edges reachable from the current scope.
func (g *SBOMGraph) NodeIDsAndEdges() FlatGraph {
	reachable := g.reachableNodes()

	nodes := make([]string, 0, len(reachable))
	for id := range reachable {
		nodes = append(nodes, id)
	}

	var edges [][2]string
	for parent, children := range g.edges {
		if !reachable[parent] {
			continue
		}
		for child := range children {
			if reachable[child] {
				edges = append(edges, [2]string{parent, child})
			}
		}
	}

	return FlatGraph{Nodes: nodes, Edges: edges}
}

// GetRootID returns the ID of the current scope root.
func (g *SBOMGraph) GetRootID() string {
	if g.scopeID != "" {
		return g.scopeID
	}
	return g.rootID
}
