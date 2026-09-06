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
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// Path is a dependency path through an SBOM, as component ids.
type Path []string

// ToStringSlice returns the path as a plain slice.
func (p Path) ToStringSlice() []string {
	return []string(p)
}

// String returns the path as a comma-separated string.
func (p Path) String() string {
	return strings.Join(p, ",")
}

// GraphRootNodeID marks the artifact itself at the head of a dependency path,
// as opposed to one of its components.
const GraphRootNodeID = "ROOT"

// SanitizeExternalReferencesURL reverts the escaping cosign applies when
// attesting, which turns each "&" into the six literal characters &.
func SanitizeExternalReferencesURL(url string) string {
	return strings.ReplaceAll(url, "\\u0026", "&")
}

// BomIsSBOM reports whether a document is an SBOM rather than a VEX report.
func BomIsSBOM(bom *cdx.BOM) bool {
	return bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) == 0
}

// ParsedSBOM is what one ingested document yields: the tree to store, and the
// component metadata that goes to the components table keyed by purl.
//
// The conversion that produces it lives in the transformer package; only the
// data lives here, so the service interfaces can name it without dragging the
// whole CycloneDX layer along.
type ParsedSBOM struct {
	Tree *MerkleTree
	// Components is keyed by component id (purl), not by bom-ref.
	Components map[string]cdx.Component
}

// SBOMSource pairs a parsed SBOM with the source it came from, so several
// upstream documents can be stored as the separate SBOMs they are rather than
// merged into one.
type SBOMSource struct {
	Source string
	SBOM   *ParsedSBOM
}

// BOMMetadata is everything needed to render an SBOM as a CycloneDX document
// that points back at this instance.
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
