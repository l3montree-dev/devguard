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
	"maps"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const ROOT = "ROOT"

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
	InfoSourceVEX  InfoSourceType = "vex"
	InfoSourceCSAF InfoSourceType = "csaf"
)

// =============================================================================
// GRAPH NODE
// =============================================================================

// GraphNode represents any node in the SBOM graph.
// All nodes (root, artifacts, info sources, components) share this structure.
type GraphNode struct {
	ID   string        // Unique identifier
	Type GraphNodeType // What kind of node this is

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
	}
	// Always create root node
	g.nodes[GraphRootNodeID] = &GraphNode{ID: GraphRootNodeID, Type: GraphNodeTypeRoot}
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
			ID:   id,
			Type: GraphNodeTypeArtifact,
			Component: &cdx.Component{
				BOMRef: id,
				Name:   name,
				Type:   cdx.ComponentTypeApplication,
			},
		}
		g.edges[id] = make(map[string]struct{})
	}
	g.edges[GraphRootNodeID][id] = struct{}{}
	return id
}

// AddInfoSource adds an information source node as a child of an artifact.
func (g *SBOMGraph) AddInfoSource(artifactID, sourceID string, sourceType InfoSourceType) string {
	id := fmt.Sprintf("%s:%s", sourceType, sourceID)
	if g.nodes[id] == nil {
		g.nodes[id] = &GraphNode{
			ID:       id,
			Type:     GraphNodeTypeInfoSource,
			InfoType: sourceType,
			Component: &cdx.Component{
				BOMRef: id,
				Name:   sourceID,
			},
		}
		g.edges[id] = make(map[string]struct{})
	}
	g.edges[artifactID][id] = struct{}{}
	return id
}

// AddComponent adds a component node.
func (g *SBOMGraph) AddComponent(comp cdx.Component) string {
	id := comp.PackageURL
	if id == "" {
		id = comp.BOMRef
	}
	if g.nodes[id] == nil {
		g.nodes[id] = &GraphNode{
			ID:        id,
			Type:      GraphNodeTypeComponent,
			Component: &comp,
		}
		g.edges[id] = make(map[string]struct{})
	}
	return id
}

// AddEdge adds a directed edge from parent to child.
func (g *SBOMGraph) AddEdge(parentID, childID string) {
	if g.edges[parentID] == nil {
		g.edges[parentID] = make(map[string]struct{})
	}
	g.edges[parentID][childID] = struct{}{}
}

// AddVulnerability adds a vulnerability.
func (g *SBOMGraph) AddVulnerability(vuln cdx.Vulnerability) {
	g.vulnerabilities[vuln.ID] = &vuln
}

func (g *SBOMGraph) ClearScope() {
	g.scopeID = g.rootID
}

func (g *SBOMGraph) Scope(id string) error {
	// check if valid
	if g.reachableNodes()[id] {
		g.scopeID = id
		return nil
	}
	return fmt.Errorf("node %s not reachable from current scope", id)
}

// =============================================================================
// MUTATIONS WITH DIFF SUPPORT
// =============================================================================

// ReplaceInfoSourceSubtree replaces an information source subtree and returns the diff.
// The newSubtree should be a graph containing:
//   - An artifact node (matching artifactID)
//   - An info source node (matching infoSourceID)
//   - All components under that info source
//
// Returns the diff of what changed (added/removed nodes and edges).
// If the info source doesn't exist, it will be added.
func (g *SBOMGraph) ReplaceInfoSourceSubtree(artifactID, infoSourceID string, newSubtree *SBOMGraph) GraphDiff {
	// Snapshot the current state for diff calculation
	oldSnapshot := g.snapshotSubtree(infoSourceID)

	// Remove the old subtree (nodes and edges under this info source)
	g.removeSubtree(infoSourceID)

	// Import the new subtree
	g.importSubtree(artifactID, infoSourceID, newSubtree)

	// Calculate diff
	newSnapshot := g.snapshotSubtree(infoSourceID)
	return g.diffSnapshots(oldSnapshot, newSnapshot)
}

// snapshotSubtree captures all nodes and edges reachable from a given node.
type subtreeSnapshot struct {
	nodes map[string]*GraphNode
	edges map[[2]string]struct{}
}

func (g *SBOMGraph) snapshotSubtree(rootID string) subtreeSnapshot {
	snapshot := subtreeSnapshot{
		nodes: make(map[string]*GraphNode),
		edges: make(map[[2]string]struct{}),
	}

	if g.nodes[rootID] == nil {
		return snapshot
	}

	var visit func(id string)
	visit = func(id string) {
		if _, seen := snapshot.nodes[id]; seen {
			return
		}
		if node := g.nodes[id]; node != nil {
			snapshot.nodes[id] = node
		}
		for childID := range g.edges[id] {
			snapshot.edges[[2]string{id, childID}] = struct{}{}
			visit(childID)
		}
	}
	visit(rootID)

	return snapshot
}

func (g *SBOMGraph) diffSnapshots(old, new subtreeSnapshot) GraphDiff {
	diff := GraphDiff{}

	// Find removed nodes
	for id, node := range old.nodes {
		if _, exists := new.nodes[id]; !exists {
			diff.RemovedNodes = append(diff.RemovedNodes, node)
		}
	}

	// Find added nodes
	for id, node := range new.nodes {
		if _, exists := old.nodes[id]; !exists {
			diff.AddedNodes = append(diff.AddedNodes, node)
		}
	}

	// Find removed edges
	for edge := range old.edges {
		if _, exists := new.edges[edge]; !exists {
			diff.RemovedEdges = append(diff.RemovedEdges, edge)
		}
	}

	// Find added edges
	for edge := range new.edges {
		if _, exists := old.edges[edge]; !exists {
			diff.AddedEdges = append(diff.AddedEdges, edge)
		}
	}

	return diff
}

// removeSubtree removes a node and all nodes reachable only through it.
// Nodes that are still reachable from other paths are kept.
func (g *SBOMGraph) removeSubtree(rootID string) {
	if g.nodes[rootID] == nil {
		return
	}

	// First, collect all nodes in the subtree
	subtreeNodes := make(map[string]bool)
	var collectSubtree func(id string)
	collectSubtree = func(id string) {
		if subtreeNodes[id] {
			return
		}
		subtreeNodes[id] = true
		for childID := range g.edges[id] {
			collectSubtree(childID)
		}
	}
	collectSubtree(rootID)

	// Remove edge from parent to this root
	for parentID, children := range g.edges {
		delete(children, rootID)
		if len(children) == 0 && parentID != g.rootID {
			// Keep empty edge sets for root
		}
	}

	// Remove the root node's edges
	delete(g.edges, rootID)

	// Remove the root node
	delete(g.nodes, rootID)

	// For other nodes in subtree, check if they're still reachable from root
	// If not, remove them
	stillReachable := g.reachableNodes()
	for nodeID := range subtreeNodes {
		if nodeID == rootID {
			continue
		}
		if !stillReachable[nodeID] {
			delete(g.nodes, nodeID)
			delete(g.edges, nodeID)
			// Also remove any edges pointing to this node
			for _, children := range g.edges {
				delete(children, nodeID)
			}
		}
	}
}

// importSubtree imports nodes and edges from another graph's info source.
func (g *SBOMGraph) importSubtree(artifactID, infoSourceID string, source *SBOMGraph) {
	// Ensure artifact exists and is connected to root
	if g.nodes[artifactID] == nil {
		_, name := ParseGraphNodeID(artifactID)
		g.AddArtifact(name)
	}

	// Find the info source in the source graph
	var sourceInfoNode *GraphNode
	for _, node := range source.nodes {
		if node.ID == infoSourceID && node.Type == GraphNodeTypeInfoSource {
			sourceInfoNode = node
			break
		}
	}

	if sourceInfoNode == nil {
		return
	}

	// Add the info source node
	g.nodes[infoSourceID] = &GraphNode{
		ID:        sourceInfoNode.ID,
		Type:      sourceInfoNode.Type,
		InfoType:  sourceInfoNode.InfoType,
		Component: sourceInfoNode.Component,
	}
	g.edges[infoSourceID] = make(map[string]struct{})

	// Connect artifact to info source
	g.AddEdge(artifactID, infoSourceID)

	// Import all nodes and edges reachable from the info source
	var importNode func(id string)
	importNode = func(id string) {
		if id == infoSourceID {
			// Already added, just process children
			for childID := range source.edges[id] {
				importNode(childID)
				g.AddEdge(id, childID)
			}
			return
		}

		sourceNode := source.nodes[id]
		if sourceNode == nil {
			return
		}

		// Add node if not exists
		if g.nodes[id] == nil {
			g.nodes[id] = &GraphNode{
				ID:        sourceNode.ID,
				Type:      sourceNode.Type,
				InfoType:  sourceNode.InfoType,
				Component: sourceNode.Component,
			}
			g.edges[id] = make(map[string]struct{})
		}

		// Process children
		for childID := range source.edges[id] {
			importNode(childID)
			g.AddEdge(id, childID)
		}
	}

	importNode(infoSourceID)
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
			ID:        node.ID,
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

// ExtractSubgraph returns a new graph containing only the subtree rooted at the given node.
// The extracted node becomes the root of the new graph.
func (g *SBOMGraph) ExtractSubgraph(nodeID string) *SBOMGraph {
	if g.nodes[nodeID] == nil {
		return nil
	}

	sub := NewSBOMGraph()

	var extract func(id string)
	extract = func(id string) {
		if sub.nodes[id] != nil {
			return // Already added
		}

		sourceNode := g.nodes[id]
		if sourceNode == nil {
			return
		}

		// Copy node
		sub.nodes[id] = &GraphNode{
			ID:        sourceNode.ID,
			Type:      sourceNode.Type,
			InfoType:  sourceNode.InfoType,
			Component: sourceNode.Component,
		}
		sub.edges[id] = make(map[string]struct{})

		// Copy children
		for childID := range g.edges[id] {
			extract(childID)
			sub.edges[id][childID] = struct{}{}
		}
	}

	extract(nodeID)

	// Connect to root
	sub.edges[GraphRootNodeID][nodeID] = struct{}{}

	return sub
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
func (g *SBOMGraph) MergeGraph(other *SBOMGraph) GraphDiff {
	beforeNodes := g.reachableNodes()
	beforeEdges := make(map[[2]string]bool)
	for parent, child := range g.Edges() {
		beforeEdges[[2]string{parent, child}] = true
	}

	// Import all nodes
	for id, node := range other.nodes {
		if id == GraphRootNodeID {
			continue // Skip root
		}
		if g.nodes[id] == nil {
			g.nodes[id] = &GraphNode{
				ID:        node.ID,
				Type:      node.Type,
				InfoType:  node.InfoType,
				Component: node.Component,
			}
			g.edges[id] = make(map[string]struct{})
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

	return diff
}

// ReplaceOrAddArtifact replaces an existing artifact subtree or adds a new one.
// Returns the diff of changes made.
func (g *SBOMGraph) ReplaceOrAddArtifact(artifactSubgraph *SBOMGraph) GraphDiff {
	// Find the artifact node in the subgraph
	var artifactID string
	for _, node := range artifactSubgraph.nodes {
		if node.Type == GraphNodeTypeArtifact {
			artifactID = node.ID
			break
		}
	}

	if artifactID == "" {
		return GraphDiff{} // No artifact found
	}

	// Check if artifact already exists
	if g.nodes[artifactID] != nil {
		// Snapshot old state
		oldSnapshot := g.snapshotSubtree(artifactID)

		// Remove old artifact subtree
		g.removeSubtree(artifactID)

		// Import new artifact subtree
		for id, node := range artifactSubgraph.nodes {
			if id == GraphRootNodeID {
				continue
			}
			g.nodes[id] = &GraphNode{
				ID:        node.ID,
				Type:      node.Type,
				InfoType:  node.InfoType,
				Component: node.Component,
			}
			g.edges[id] = make(map[string]struct{})
		}

		for parentID, children := range artifactSubgraph.edges {
			if parentID == GraphRootNodeID {
				for childID := range children {
					g.edges[g.rootID][childID] = struct{}{}
				}
			} else {
				for childID := range children {
					g.AddEdge(parentID, childID)
				}
			}
		}

		// Calculate diff
		newSnapshot := g.snapshotSubtree(artifactID)
		return g.diffSnapshots(oldSnapshot, newSnapshot)
	}

	// Artifact doesn't exist, just merge
	return g.MergeGraph(artifactSubgraph)
}

// GetArtifactIDs returns all artifact IDs in the graph.
func (g *SBOMGraph) GetArtifactIDs() []string {
	var ids []string
	for artifact := range g.Artifacts() {
		ids = append(ids, artifact.ID)
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
		var visit func(id string)
		visit = func(id string) {
			if visited[id] {
				return
			}
			visited[id] = true

			if node := g.nodes[id]; node != nil && node.Type == nodeType {
				if !yield(node) {
					return
				}
			}

			for childID := range g.edges[id] {
				visit(childID)
			}
		}
		visit(g.scopeID)
	}
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
		visit(infoSource.ID)
	}

	return result
}

// ComponentsWithMultipleSources returns component IDs that appear in multiple SBOMs or have VEX/CSAF.
// These cannot be automatically marked as "fixed".
func (g *SBOMGraph) ComponentsWithMultipleSources() []string {
	counts := g.CountInfoSourcesPerComponent()
	var result []string

	for id, typeCounts := range counts {
		if typeCounts[InfoSourceSBOM] > 1 || typeCounts[InfoSourceVEX] > 0 || typeCounts[InfoSourceCSAF] > 0 {
			result = append(result, id)
		}
	}

	return result
}

// CalculateDepth returns the minimum depth of each component from info source roots.
// Depth 1 = direct child of info source, depth 2 = grandchild, etc.
func (g *SBOMGraph) CalculateDepth() map[string]int {
	depths := make(map[string]int)

	type item struct {
		id    string
		depth int
	}
	queue := []item{}

	// Start BFS from all info source children (the root components)
	for infoSource := range g.InfoSources() {
		for childID := range g.edges[infoSource.ID] {
			if node := g.nodes[childID]; node != nil && node.Type == GraphNodeTypeComponent {
				queue = append(queue, item{id: childID, depth: 1})
			}
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if existing, ok := depths[curr.id]; ok && existing <= curr.depth {
			continue
		}
		depths[curr.id] = curr.depth

		for childID := range g.edges[curr.id] {
			if node := g.nodes[childID]; node != nil && node.Type == GraphNodeTypeComponent {
				queue = append(queue, item{id: childID, depth: curr.depth + 1})
			}
		}
	}

	return depths
}

// FindAllPathsTo finds all paths from info source roots to a target component.
func (g *SBOMGraph) FindAllPathsTo(targetID string) [][]string {
	var paths [][]string

	var visit func(id string, path []string, visited map[string]bool)
	visit = func(id string, path []string, visited map[string]bool) {
		if visited[id] {
			return
		}

		newPath := append(append([]string{}, path...), id)
		newVisited := make(map[string]bool)
		maps.Copy(newVisited, visited)
		newVisited[id] = true

		if id == targetID {
			paths = append(paths, newPath)
			return
		}

		for childID := range g.edges[id] {
			visit(childID, newPath, newVisited)
		}
	}

	// Start from info source children
	for infoSource := range g.InfoSources() {
		for childID := range g.edges[infoSource.ID] {
			visit(childID, []string{}, make(map[string]bool))
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
		ids[i] = n.ID
	}
	return ids
}

// RemovedNodeIDs returns just the IDs of removed nodes.
func (d GraphDiff) RemovedNodeIDs() []string {
	ids := make([]string, len(d.RemovedNodes))
	for i, n := range d.RemovedNodes {
		ids[i] = n.ID
	}
	return ids
}

// Diff compares this graph with another and returns the differences.
func (g *SBOMGraph) Diff(other *SBOMGraph) GraphDiff {
	diff := GraphDiff{}

	thisNodes := g.reachableNodes()
	otherNodes := other.reachableNodes()

	for id := range thisNodes {
		if !otherNodes[id] {
			if node := g.nodes[id]; node != nil {
				diff.RemovedNodes = append(diff.RemovedNodes, node)
			}
		}
	}
	for id := range otherNodes {
		if !thisNodes[id] {
			if node := other.nodes[id]; node != nil {
				diff.AddedNodes = append(diff.AddedNodes, node)
			}
		}
	}

	thisEdges := make(map[[2]string]bool)
	for parent, child := range g.Edges() {
		thisEdges[[2]string{parent, child}] = true
	}

	otherEdges := make(map[[2]string]bool)
	for parent, child := range other.Edges() {
		otherEdges[[2]string{parent, child}] = true
	}

	for edge := range thisEdges {
		if !otherEdges[edge] {
			diff.RemovedEdges = append(diff.RemovedEdges, edge)
		}
	}
	for edge := range otherEdges {
		if !thisEdges[edge] {
			diff.AddedEdges = append(diff.AddedEdges, edge)
		}
	}

	return diff
}

// =============================================================================
// EXPORT
// =============================================================================

// ToCycloneDX exports the scoped view as a CycloneDX BOM.
func (g *SBOMGraph) ToCycloneDX(rootName string) *cdx.BOM {
	components := []cdx.Component{}
	for node := range g.Components() {
		if node.Component != nil {
			components = append(components, *node.Component)
		}
	}

	// Build dependency map: component -> its component children
	depMap := make(map[string][]string)
	depMap[rootName] = []string{}

	for parent, child := range g.ComponentEdges() {
		depMap[parent] = append(depMap[parent], child)
	}

	// Root's direct deps are the first-level components (children of info sources)
	for infoSource := range g.InfoSources() {
		for childID := range g.edges[infoSource.ID] {
			if node := g.nodes[childID]; node != nil && node.Type == GraphNodeTypeComponent {
				depMap[rootName] = append(depMap[rootName], childID)
			}
		}
	}

	dependencies := []cdx.Dependency{}
	for ref, deps := range depMap {
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &deps,
		})
	}

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
				BOMRef: rootName,
				Name:   rootName,
				Type:   cdx.ComponentTypeApplication,
			},
		},
		Components:      &components,
		Dependencies:    &dependencies,
		Vulnerabilities: &vulns,
	}
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

func (g *SBOMGraph) isReachable(id string) bool {
	return g.reachableNodes()[id]
}

// =============================================================================
// BUILDER
// =============================================================================

// SBOMGraphBuilder provides a fluent API for constructing graphs.
type SBOMGraphBuilder struct {
	graph             *SBOMGraph
	currentArtifact   string
	currentInfoSource string
}

// NewSBOMGraphBuilder creates a new builder.
func NewSBOMGraphBuilder() *SBOMGraphBuilder {
	return &SBOMGraphBuilder{graph: NewSBOMGraph()}
}

// Artifact sets the current artifact context.
func (b *SBOMGraphBuilder) Artifact(name string) *SBOMGraphBuilder {
	b.currentArtifact = b.graph.AddArtifact(name)
	b.currentInfoSource = "" // Reset info source when changing artifact
	return b
}

// InfoSource sets the current info source context (requires artifact).
func (b *SBOMGraphBuilder) InfoSource(sourceID string, sourceType InfoSourceType) *SBOMGraphBuilder {
	if b.currentArtifact == "" {
		panic("must set artifact before info source")
	}
	b.currentInfoSource = b.graph.AddInfoSource(b.currentArtifact, sourceID, sourceType)
	return b
}

// Component adds a component as a root of the current info source.
func (b *SBOMGraphBuilder) Component(comp cdx.Component) *SBOMGraphBuilder {
	if b.currentInfoSource == "" {
		panic("must set info source before adding components")
	}
	compID := b.graph.AddComponent(comp)
	b.graph.AddEdge(b.currentInfoSource, compID)
	return b
}

// Dependency adds a dependency edge between two components.
func (b *SBOMGraphBuilder) Dependency(parentPurl, childPurl string) *SBOMGraphBuilder {
	// Ensure both components exist
	if b.graph.nodes[parentPurl] == nil {
		b.graph.AddComponent(cdx.Component{BOMRef: parentPurl, PackageURL: parentPurl})
	}
	if b.graph.nodes[childPurl] == nil {
		b.graph.AddComponent(cdx.Component{BOMRef: childPurl, PackageURL: childPurl})
	}
	b.graph.AddEdge(parentPurl, childPurl)
	return b
}

// Vulnerability adds a vulnerability.
func (b *SBOMGraphBuilder) Vulnerability(vuln cdx.Vulnerability) *SBOMGraphBuilder {
	b.graph.AddVulnerability(vuln)
	return b
}

// Build returns the constructed graph.
func (b *SBOMGraphBuilder) Build() *SBOMGraph {
	return b.graph
}

func getInfoSourceTypeByInspectingSBOM(bom *cdx.BOM) InfoSourceType {
	// Default to SBOM
	infoSourceType := InfoSourceSBOM

	// Inspect vulnerabilities for VEX indicators
	if bom.Vulnerabilities != nil {
		return InfoSourceVEX
	}
	return infoSourceType
}

// =============================================================================
// PARSING FROM CYCLONEDX
// =============================================================================

// SBOMGraphFromCycloneDX creates an SBOMGraph from a CycloneDX BOM.
func SBOMGraphFromCycloneDX(bom *cdx.BOM, artifactName, infoSourceID string) *SBOMGraph {
	g := NewSBOMGraph()

	artifactID := g.AddArtifact(artifactName)

	// extract the info source type from the infoSourceID
	infoSourceType := getInfoSourceTypeByInspectingSBOM(bom)

	infoID := g.AddInfoSource(artifactID, infoSourceID, infoSourceType)

	// Add all components
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			g.AddComponent(comp)
		}
	}

	// Build dependency map
	depMap := make(map[string][]string)
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies != nil {
				depMap[dep.Ref] = *dep.Dependencies
			}
		}
	}

	// Find root ref
	rootRef := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		rootRef = bom.Metadata.Component.BOMRef
	}

	// Add edges
	for parent, children := range depMap {
		// If parent is root, add as info source children
		if parent == rootRef || parent == "" || parent == ROOT {
			for _, child := range children {
				if g.nodes[child] != nil {
					g.AddEdge(infoID, child)
				}
			}
		} else {
			// Component to component edge
			for _, child := range children {
				if g.nodes[parent] != nil && g.nodes[child] != nil {
					g.AddEdge(parent, child)
				}
			}
		}
	}

	// If no explicit root dependencies, all components are roots
	if len(depMap[rootRef]) == 0 && len(depMap[""]) == 0 {
		if bom.Components != nil {
			for _, comp := range *bom.Components {
				purl := comp.PackageURL
				if purl == "" {
					purl = comp.BOMRef
				}
				// Check if this component is a child of any other
				isChild := false
				for _, children := range depMap {
					for _, child := range children {
						if child == purl {
							isChild = true
							break
						}
					}
					if isChild {
						break
					}
				}
				if !isChild {
					g.AddEdge(infoID, purl)
				}
			}
		}
	}

	// Add vulnerabilities
	if bom.Vulnerabilities != nil {
		for _, vuln := range *bom.Vulnerabilities {
			g.AddVulnerability(vuln)
		}
	}

	return g
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
	ToCdxComponent(componentLicenseOverwrites map[string]string) cdx.Component
}

// SBOMGraphFromComponents builds an SBOMGraph from database components.
// The components include artifact nodes, information source nodes, and regular components.
// This function reconstructs the full graph structure from the flat component list.
func SBOMGraphFromComponents(components []GraphComponent, licenseOverwrites map[string]string) *SBOMGraph {
	g := NewSBOMGraph()

	// Build dependency map: parent -> children
	dependencyMap := make(map[string][]string)
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

		cdxComp := comp.ToCdxComponent(licenseOverwrites)

		// Determine node type from ID prefix
		prefix, name := ParseGraphNodeID(id)
		switch prefix {
		case "artifact":
			g.nodes[id] = &GraphNode{
				ID:   id,
				Type: GraphNodeTypeArtifact,
				Component: &cdx.Component{
					BOMRef: id,
					Name:   name,
					Type:   cdx.ComponentTypeApplication,
				},
			}
			g.edges[id] = make(map[string]struct{})
		case string(InfoSourceSBOM), string(InfoSourceVEX), string(InfoSourceCSAF):
			g.nodes[id] = &GraphNode{
				ID:        id,
				Type:      GraphNodeTypeInfoSource,
				InfoType:  InfoSourceType(prefix),
				Component: &cdxComp,
			}
			g.edges[id] = make(map[string]struct{})
		default:
			// Regular component
			g.nodes[id] = &GraphNode{
				ID:        id,
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

	return g
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
