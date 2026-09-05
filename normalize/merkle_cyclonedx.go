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

package normalize

import (
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// ParsedSBOM is what one ingested document yields: the tree to store, and the
// component metadata that goes to the components table keyed by purl.
type ParsedSBOM struct {
	Tree *MerkleTree
	// Components is keyed by component id (purl), not by bom-ref.
	Components map[string]cdx.Component
}

// merkleParseRoot is the synthetic ref the document hangs off. It never reaches
// the database - the root is hashed under the artifact's own identity.
const merkleParseRoot = "\x00sbom-root"

// MerkleTreeFromCycloneDX parses a CycloneDX document into a content-addressed
// tree rooted at artifactName.
//
// Components without an identifiable purl are dropped and their dependencies
// reparented onto their own parents, so an unidentifiable intermediate does not
// disconnect the subtree beneath it.
func MerkleTreeFromCycloneDX(bom *cdx.BOM, artifactName string) (*ParsedSBOM, error) {
	if err := validateCycloneDX(bom); err != nil {
		return nil, err
	}

	rootComponent := bom.Metadata.Component
	rootRef := rootComponent.BOMRef

	components := map[string]cdx.Component{}
	// componentIDs maps bom-ref -> purl, and doubles as the set of known refs
	componentIDs := map[string]string{}

	addComponent := func(comp cdx.Component) {
		componentIDs[comp.BOMRef] = comp.PackageURL
		if looksLikePackagePURL(comp.PackageURL) {
			components[comp.PackageURL] = comp
		}
	}
	addComponent(*rootComponent)

	seen := map[string]bool{}
	if bom.Components != nil {
		for idx, comp := range *bom.Components {
			if comp.BOMRef == "" {
				return nil, fmt.Errorf("component at index %d has missing BOMRef", idx)
			}
			if comp.Name == "" {
				comp.Name = comp.BOMRef
			}
			if seen[comp.BOMRef] {
				slog.Warn("duplicate BOMRef found, skipping component", "bomRef", comp.BOMRef)
				continue
			}
			seen[comp.BOMRef] = true

			if err := validateCycloneDXComponent(comp); err != nil {
				return nil, err
			}
			addComponent(sanitizeCycloneDXComponent(comp))
		}
	}

	children := buildMerkleDependencyMap(bom, rootRef, componentIDs)

	// Hang the document off a synthetic root. If the document's own root
	// component IS this artifact - a devguard SBOM being re-uploaded, or a
	// scanner naming the container root after the image - its children are
	// reparented onto the synthetic root, otherwise the artifact would end up
	// depending on itself.
	if isArtifactRootComponent(rootComponent, artifactName) {
		children[merkleParseRoot] = slices.Clone(children[rootRef])
	} else {
		children[merkleParseRoot] = []string{rootRef}
	}

	pruneUnidentifiableRefs(children, componentIDs)

	tree := BuildMerkleTree(
		Adjacency{Children: children, ComponentIDs: componentIDs},
		merkleParseRoot,
		artifactName,
	)
	return &ParsedSBOM{Tree: tree, Components: components}, nil
}

// rootName is the identity of the emitted root component: the caller's override
// if given, otherwise the artifact at this asset version.
func (m BOMMetadata) rootName() string {
	if m.RootName != "" {
		return m.RootName
	}
	// keep the version ahead of any qualifiers, e.g. pkg:oci/n@v?k=v
	if p, err := packageurl.FromString(m.ArtifactName); err == nil && m.AssetVersionName != "" {
		p.Version = m.AssetVersionName
		return p.String()
	}
	return fmt.Sprintf("%s@%s", m.ArtifactName, m.AssetVersionName)
}

func (m BOMMetadata) externalReferences() *[]cdx.ExternalReference {
	if !m.AddExternalReferences {
		return nil
	}

	apiURL := os.Getenv("API_URL")
	// QueryEscape, not PathEscape: artifact names may be purls, so colons count
	escapedArtifactName := url.QueryEscape(m.ArtifactName)

	refs := []cdx.ExternalReference{{
		URL:     fmt.Sprintf("%s/api/v1/public/%s/refs/%s/artifacts/%s/vex.json/", apiURL, m.AssetID.String(), m.AssetVersionSlug, escapedArtifactName),
		Comment: "Up to date Vulnerability exploitability information.",
		Type:    cdx.ERTypeExploitabilityStatement,
	}, {
		URL:     fmt.Sprintf("%s/api/v1/public/%s/refs/%s/artifacts/%s/sbom.json/", apiURL, m.AssetID.String(), m.AssetVersionSlug, escapedArtifactName),
		Comment: "Software bill of materials.",
		Type:    cdx.ERTypeBOM,
	}}

	if dashboardURL := getDashboardURL(m, escapedArtifactName); dashboardURL != "" {
		refs = append(refs, cdx.ExternalReference{
			URL:     dashboardURL,
			Comment: "Dynamic analysis report",
			Type:    cdx.ERTypeDynamicAnalysisReport,
		})
	}
	return &refs
}

// ToCycloneDX renders the tree back into a CycloneDX document.
//
// components supplies the metadata (licenses, types, hashes) that the tree
// itself does not carry; it is keyed by component id. A component missing from
// it is emitted with just its purl.
func (t *MerkleTree) ToCycloneDX(metadata BOMMetadata, components map[string]cdx.Component) *cdx.BOM {
	rootName := metadata.rootName()
	rootPURL := ""
	if p, err := packageurl.FromString(rootName); err == nil {
		rootPURL = p.String()
	}

	emitted := []cdx.Component{}
	for _, id := range t.ComponentIDs() {
		if comp, ok := components[id]; ok {
			emitted = append(emitted, comp)
			continue
		}
		emitted = append(emitted, cdx.Component{
			BOMRef:     id,
			Name:       id,
			PackageURL: id,
			Type:       cdx.ComponentTypeLibrary,
		})
	}

	rootComponent := cdx.Component{
		BOMRef:     rootName,
		Name:       rootName,
		Type:       cdx.ComponentTypeApplication,
		PackageURL: rootPURL,
	}
	emitted = append(emitted, rootComponent)

	depMap := map[string][]string{rootName: {}}
	for node := range t.MerkleNodes() {
		parent := node.ComponentID
		if node.SubtreeHash == t.Root {
			parent = rootName
		}
		for _, childHash := range node.Children {
			child := t.Node(childHash)
			if child == nil || child.ComponentID == parent {
				continue
			}
			if !slices.Contains(depMap[parent], child.ComponentID) {
				depMap[parent] = append(depMap[parent], child.ComponentID)
			}
		}
	}

	dependencies := make([]cdx.Dependency, 0, len(emitted))
	for _, comp := range emitted {
		deps := depMap[comp.BOMRef]
		if deps == nil {
			deps = []string{} // an empty array, not null, per spec
		}
		dependencies = append(dependencies, cdx.Dependency{Ref: comp.BOMRef, Dependencies: &deps})
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
				PackageURL: rootPURL,
			},
		},
		Components:         &emitted,
		Dependencies:       &dependencies,
		ExternalReferences: metadata.externalReferences(),
	}
}

func validateCycloneDX(bom *cdx.BOM) error {
	if bom == nil {
		return fmt.Errorf("BOM cannot be nil")
	}
	if bom.BOMFormat != "CycloneDX" {
		return fmt.Errorf("invalid BOM format: %s (expected CycloneDX)", bom.BOMFormat)
	}
	if bom.SpecVersion < 1 {
		return fmt.Errorf("BOM spec version must be >= 1, got %d", bom.SpecVersion)
	}
	if bom.Metadata == nil {
		return fmt.Errorf("BOM metadata is required")
	}
	if bom.Metadata.Component == nil {
		return fmt.Errorf("metadata component is required")
	}
	if bom.Metadata.Component.BOMRef == "" {
		return fmt.Errorf("root component BOMRef is required")
	}
	if bom.Metadata.Component.Name == "" {
		return fmt.Errorf("root component name is required")
	}
	if purl := bom.Metadata.Component.PackageURL; purl != "" {
		if _, err := packageurl.FromString(purl); err != nil {
			return fmt.Errorf("invalid root component PackageURL: %w", err)
		}
	}
	return nil
}

func validateCycloneDXComponent(comp cdx.Component) error {
	if comp.PackageURL != "" {
		if _, err := packageurl.FromString(comp.PackageURL); err != nil {
			return fmt.Errorf("component %s has invalid PackageURL: %w", comp.BOMRef, err)
		}
	}
	if comp.Scope != "" {
		validScopes := map[cdx.Scope]bool{
			cdx.ScopeExcluded: true,
			cdx.ScopeOptional: true,
			cdx.ScopeRequired: true,
		}
		if !validScopes[comp.Scope] {
			return fmt.Errorf("component %s has invalid scope: %s", comp.BOMRef, comp.Scope)
		}
	}
	return nil
}

// sanitizeCycloneDXComponent drops invalid hashes and external reference types
// rather than rejecting the whole document over them.
func sanitizeCycloneDXComponent(comp cdx.Component) cdx.Component {
	if comp.Hashes != nil {
		valid := []cdx.Hash{}
		for _, hash := range *comp.Hashes {
			if isValidHashAlgorithm(hash.Algorithm) {
				valid = append(valid, hash)
			}
		}
		if len(valid) > 0 {
			comp.Hashes = &valid
		} else {
			comp.Hashes = nil
		}
	}
	if comp.ExternalReferences != nil {
		valid := []cdx.ExternalReference{}
		for _, ref := range *comp.ExternalReferences {
			if isValidExternalReferenceType(ref.Type) {
				valid = append(valid, ref)
			}
		}
		if len(valid) > 0 {
			comp.ExternalReferences = &valid
		} else {
			comp.ExternalReferences = nil
		}
	}
	return comp
}

// buildMerkleDependencyMap turns the document's dependency list into a ref ->
// child refs map. When the document declares no dependencies for the root, every
// component that is nobody's child becomes a direct dependency.
func buildMerkleDependencyMap(bom *cdx.BOM, rootRef string, componentIDs map[string]string) map[string][]string {
	known := make(map[string]*GraphNode, len(componentIDs))
	for ref := range componentIDs {
		known[ref] = &GraphNode{BOMRef: ref}
	}
	children := buildFilteredDependencyMap(bom.Dependencies, known, rootRef)

	if len(children[rootRef]) == 0 && bom.Components != nil {
		isChild := map[string]bool{}
		for _, refs := range children {
			for _, ref := range refs {
				isChild[ref] = true
			}
		}
		for _, comp := range *bom.Components {
			if !isChild[comp.BOMRef] {
				children[rootRef] = append(children[rootRef], comp.BOMRef)
			}
		}
	}
	return children
}

// pruneUnidentifiableRefs removes refs whose component id is not a package purl,
// reparenting their children onto their parents so the subtree below them stays
// reachable.
func pruneUnidentifiableRefs(children map[string][]string, componentIDs map[string]string) {
	identifiable := func(ref string) bool {
		return ref == merkleParseRoot || looksLikePackagePURL(componentIDs[ref])
	}

	// nearest identifiable descendants of a ref, memoized. onStack keeps a
	// cycle of unidentifiable refs from recursing forever.
	memo := map[string][]string{}
	var resolve func(ref string, onStack map[string]bool) []string
	resolve = func(ref string, onStack map[string]bool) []string {
		if cached, ok := memo[ref]; ok {
			return cached
		}
		if onStack[ref] {
			return nil
		}
		onStack[ref] = true
		defer delete(onStack, ref)

		var out []string
		add := func(candidate string) {
			if !slices.Contains(out, candidate) {
				out = append(out, candidate)
			}
		}
		for _, child := range children[ref] {
			if identifiable(child) {
				add(child)
				continue
			}
			for _, descendant := range resolve(child, onStack) {
				add(descendant)
			}
		}
		memo[ref] = out
		return out
	}

	pruned := map[string][]string{}
	for ref := range children {
		if identifiable(ref) {
			pruned[ref] = resolve(ref, map[string]bool{})
		}
	}

	clear(children)
	maps.Copy(children, pruned)
}
