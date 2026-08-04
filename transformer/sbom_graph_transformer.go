// Copyright (C) 2026 l3montree GmbH
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

package transformer

import (
	"slices"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
)

func hash(purl string, subtreeHashes []string) string {
	// join the strings together and hash the result
	// it is mandatory they stay in the same order, otherwise the hash will be different
	slices.SortStableFunc(subtreeHashes, strings.Compare)
	return utils.HashString(purl + "->" + strings.Join(subtreeHashes, ";"))
}

func SBOMGraphToMerkleTree(sbomGraph *normalize.SBOMGraph) []models.SBOMMerkleEdge {
	// compute the hash of the root node - which will recursively compute the hashes of all nodes in the graph and extract the edges into a list of SBOMMerkleEdges
	hashMap := make(map[string]string)
	rootNode := sbomGraph.Nodes[sbomGraph.RootID]
	_ = computeSubtreeHashes(hashMap, sbomGraph, rootNode)

	merkleEdges := make([]models.SBOMMerkleEdge, 0, len(hashMap))
	for _, node := range sbomGraph.Nodes {
		subtreeHash := hashMap[node.BOMRef]
		for childID := range sbomGraph.Edges[node.BOMRef] {
			childSubtreeHash := hashMap[childID]
			merkleEdges = append(merkleEdges, models.SBOMMerkleEdge{
				SubtreeHash:                 subtreeHash,
				ComponentID:                 node.BOMRef,
				DirectDependencySubtreeHash: childSubtreeHash,
			})
		}
	}
	return merkleEdges
}

func computeSubtreeHashes(hashMap map[string]string, sbomGraph *normalize.SBOMGraph, node *normalize.GraphNode) string {
	if hash, exists := hashMap[node.BOMRef]; exists {
		// this node has already been processed, we can skip it
		return hash
	}
	if len(sbomGraph.Edges[node.BOMRef]) == 0 {
		// this is a leaf node, we can compute its hash directly
		hashMap[node.BOMRef] = hash(node.Component.PackageURL, nil)
	} else {
		// this is not a leaf node, we need to compute the hashes of the children first
		childHashes := []string{}
		for childID := range sbomGraph.Edges[node.BOMRef] {
			childHashes = append(childHashes, computeSubtreeHashes(hashMap, sbomGraph, sbomGraph.Nodes[childID]))
		}
		hashMap[node.BOMRef] = hash(node.Component.PackageURL, childHashes)
	}
	return hashMap[node.BOMRef]
}
