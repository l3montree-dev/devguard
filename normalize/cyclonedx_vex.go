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
	"net/url"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

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

// dedupVexVulnerabilities collapses vulnerabilities that share the same CVE id and affected
// refs, keeping the one with the highest-priority analysis state. This mirrors CycloneDX's
// inherent inability to distinguish multiple dependency paths to the same component - the
// accepted limitation of the CycloneDX VEX format.
func dedupVexVulnerabilities(vulns []cdx.Vulnerability) []cdx.Vulnerability {
	type entry struct {
		vuln  cdx.Vulnerability
		order int
	}
	byKey := make(map[string]*entry)
	order := 0
	for _, vuln := range vulns {
		var affects strings.Builder
		if vuln.Affects != nil {
			for _, aff := range *vuln.Affects {
				affects.WriteString(aff.Ref + ";")
			}
		}
		key := vuln.ID + "@" + affects.String()

		existing, ok := byKey[key]
		if !ok {
			byKey[key] = &entry{vuln: vuln, order: order}
			order++
			continue
		}

		existingState := cdx.ImpactAnalysisState("")
		if existing.vuln.Analysis != nil {
			existingState = existing.vuln.Analysis.State
		}
		newState := cdx.ImpactAnalysisState("")
		if vuln.Analysis != nil {
			newState = vuln.Analysis.State
		}
		if statePriority(newState) > statePriority(existingState) {
			existing.vuln = vuln
		}
	}

	result := make([]cdx.Vulnerability, len(byKey))
	for _, e := range byKey {
		result[e.order] = e.vuln
	}
	return result
}

// CycloneDXVEXFromVulnerabilities builds a CycloneDX VEX BOM directly from a set of
// vulnerabilities, without going through an SBOMGraph. The affected components (from each
// vulnerability's Affects refs) become the BOM's components, all declared as direct
// dependencies of the root component described by metadata.
func CycloneDXVEXFromVulnerabilities(vulns []cdx.Vulnerability, metadata BOMMetadata) *cdx.BOM {
	deduped := dedupVexVulnerabilities(vulns)

	rootName := metadata.RootName
	if rootName == "" {
		// If ArtifactName is a valid PURL, parse it and set the version properly so that the
		// version appears before qualifiers (e.g. pkg:oci/name@version?qualifier=value).
		if p, err := packageurl.FromString(metadata.ArtifactName); err == nil && metadata.AssetVersionName != "" {
			p.Version = metadata.AssetVersionName
			rootName = p.String()
		} else {
			rootName = fmt.Sprintf("%s@%s", metadata.ArtifactName, metadata.AssetVersionName)
		}
	}

	pURL := ""
	if p, err := packageurl.FromString(rootName); err == nil {
		pURL = p.String()
	}

	// collect the affected components (deduplicated by ref)
	components := []cdx.Component{}
	rootDeps := []string{}
	seen := map[string]bool{}
	for _, vuln := range deduped {
		if vuln.Affects == nil {
			continue
		}
		for _, aff := range *vuln.Affects {
			ref := aff.Ref
			if ref == "" || seen[ref] {
				continue
			}
			// only real package URLs become components (matches SBOMGraphFromVulnerabilities)
			purl, err := packageurl.FromString(ref)
			if err != nil {
				continue
			}
			seen[ref] = true

			packageURL := ref
			if unescaped, err := url.PathUnescape(ref); err == nil {
				packageURL = unescaped
			}
			components = append(components, cdx.Component{
				BOMRef:     ref,
				Name:       purl.Name,
				Version:    purl.Version,
				PackageURL: packageURL,
				Type:       cdx.ComponentTypeLibrary,
			})
			rootDeps = append(rootDeps, ref)
		}
	}

	rootComponent := cdx.Component{
		BOMRef:     rootName,
		Name:       rootName,
		Type:       cdx.ComponentTypeApplication,
		PackageURL: pURL,
	}
	components = append(components, rootComponent)

	// dependencies: each affected component has no children; the root depends on all of them
	dependencies := make([]cdx.Dependency, 0, len(components))
	for _, ref := range rootDeps {
		empty := []string{}
		dependencies = append(dependencies, cdx.Dependency{Ref: ref, Dependencies: &empty})
	}
	dependencies = append(dependencies, cdx.Dependency{Ref: rootName, Dependencies: &rootDeps})

	return &cdx.BOM{
		SpecVersion: cdx.SpecVersion1_6,
		BOMFormat:   "CycloneDX",
		Version:     1,
		Metadata: &cdx.Metadata{
			Component: &rootComponent,
		},
		Components:         &components,
		Dependencies:       &dependencies,
		Vulnerabilities:    &deduped,
		ExternalReferences: vexExternalReferences(metadata),
	}
}

// MergeCycloneDXVEX merges several CycloneDX VEX BOMs into one under a single release root.
// Because the components and dependencies are derived from the vulnerabilities' affected
// refs, merging is simply rebuilding the BOM from the union of all vulnerabilities.
func MergeCycloneDXVEX(boms []*cdx.BOM, rootName string) *cdx.BOM {
	var vulns []cdx.Vulnerability
	for _, b := range boms {
		if b != nil && b.Vulnerabilities != nil {
			vulns = append(vulns, *b.Vulnerabilities...)
		}
	}
	return CycloneDXVEXFromVulnerabilities(vulns, BOMMetadata{RootName: rootName})
}

// vexExternalReferences builds the up-to-date VEX / SBOM / dashboard external references for
// a VEX BOM when the asset shares information.
func vexExternalReferences(metadata BOMMetadata) *[]cdx.ExternalReference {
	if !metadata.AddExternalReferences {
		return nil
	}

	apiURL := os.Getenv("API_URL")
	// Use QueryEscape to encode all special characters including colons; PathEscape is too
	// lenient for artifact names which may contain PURLs or other special chars.
	escapedArtifactName := url.QueryEscape(metadata.ArtifactName)

	vexURL := fmt.Sprintf("%s/api/v1/public/%s/refs/%s/artifacts/%s/vex.json/", apiURL, metadata.AssetID.String(), metadata.AssetVersionSlug, escapedArtifactName)
	sbomURL := fmt.Sprintf("%s/api/v1/public/%s/refs/%s/artifacts/%s/sbom.json/", apiURL, metadata.AssetID.String(), metadata.AssetVersionSlug, escapedArtifactName)

	refs := []cdx.ExternalReference{
		{URL: vexURL, Comment: "Up to date Vulnerability exploitability information.", Type: cdx.ERTypeExploitabilityStatement},
		{URL: sbomURL, Comment: "Software bill of materials.", Type: cdx.ERTypeBOM},
	}

	if dashboardURL := getDashboardURL(metadata, escapedArtifactName); dashboardURL != "" {
		refs = append(refs, cdx.ExternalReference{
			URL:     dashboardURL,
			Comment: "Dynamic analysis report",
			Type:    cdx.ERTypeDynamicAnalysisReport,
		})
	}

	return &refs
}
