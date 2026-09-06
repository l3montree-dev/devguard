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
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
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

// SanitizeExternalReferencesURL reverts the escaping cosign applies when
// attesting, which turns each "&" into the six literal characters &.
func SanitizeExternalReferencesURL(url string) string {
	return strings.ReplaceAll(url, "\\u0026", "&")
}

// BomIsSBOM reports whether a document is an SBOM rather than a VEX report.
func BomIsSBOM(bom *cdx.BOM) bool {
	return bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) == 0
}

func getDashboardURL(metadata BOMMetadata, escapedArtifactName string) string {
	if metadata.FrontendURL == "" || metadata.OrgSlug == "" || metadata.ProjectSlug == "" || metadata.AssetSlug == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/projects/%s/assets/%s/refs/%s?artifact=%s",
		metadata.FrontendURL, metadata.OrgSlug, metadata.ProjectSlug, metadata.AssetSlug,
		metadata.AssetVersionSlug, escapedArtifactName)
}

func looksLikePackagePURL(id string) bool {
	return strings.HasPrefix(id, "pkg:") && strings.Contains(id, "@")
}

// isArtifactRootComponent reports whether a document's root component is the
// artifact itself - a devguard SBOM being re-uploaded, or a scanner naming a
// container root after the image it scanned. Linking to it would then make the
// artifact depend on itself.
//
// Only PURLs are compared. Artifact names are frequently plain human-chosen
// strings, so matching on Name alone would misfire on ordinary scans.
func isArtifactRootComponent(rootComponent *cdx.Component, artifactName string) bool {
	if rootComponent.PackageURL == "" {
		return false
	}
	rootPurl, err := packageurl.FromString(rootComponent.PackageURL)
	if err != nil {
		return false
	}
	artifactPurl, err := packageurl.FromString(artifactName)
	if err != nil {
		return false
	}
	return rootPurl.Type == artifactPurl.Type &&
		rootPurl.Namespace == artifactPurl.Namespace &&
		rootPurl.Name == artifactPurl.Name
}

// sanitizeComponentType falls back to Library, since an invalid type would fail
// CycloneDX schema validation on export.
func sanitizeComponentType(ct cdx.ComponentType) cdx.ComponentType {
	if validComponentTypes[ct] {
		return ct
	}
	return cdx.ComponentTypeLibrary
}

var validComponentTypes = map[cdx.ComponentType]bool{
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

var validHashAlgorithms = map[cdx.HashAlgorithm]bool{
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

var validExternalReferenceTypes = map[cdx.ExternalReferenceType]bool{
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

func isValidHashAlgorithm(alg cdx.HashAlgorithm) bool {
	return validHashAlgorithms[alg]
}

func isValidExternalReferenceType(t cdx.ExternalReferenceType) bool {
	return validExternalReferenceTypes[t]
}
