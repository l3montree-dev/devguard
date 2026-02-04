package normalize

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cycloneDXSchemaURL is the CycloneDX 1.6 JSON schema URL
const cycloneDXSchemaURL = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json"

var (
	schemaOnce   sync.Once
	cachedSchema *jsonschema.Schema
	schemaErr    error
)

// httpURLLoader implements jsonschema.URLLoader for HTTP URLs
type httpURLLoader struct{}

func (httpURLLoader) Load(url string) (any, error) {
	resp, err := http.Get(url) //nolint:gosec,noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

// compileSchema compiles the CycloneDX JSON schema for validation
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	schemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.UseLoader(httpURLLoader{})
		cachedSchema, schemaErr = compiler.Compile(cycloneDXSchemaURL)
	})

	require.NoError(t, schemaErr, "Failed to compile CycloneDX schema")
	return cachedSchema
}

// validateBOMAgainstSchema validates a CycloneDX BOM against the JSON schema
func validateBOMAgainstSchema(t *testing.T, bom *cdx.BOM, schema *jsonschema.Schema) {
	t.Helper()

	// Encode BOM to JSON
	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	err := encoder.Encode(bom)
	require.NoError(t, err, "Failed to encode BOM to JSON")

	// Parse JSON for schema validation
	var jsonData any
	err = json.Unmarshal(buf.Bytes(), &jsonData)
	require.NoError(t, err, "Failed to parse BOM JSON")

	// Validate against schema
	err = schema.Validate(jsonData)
	if err != nil {
		t.Logf("BOM JSON:\n%s", buf.String())
	}
	assert.NoError(t, err, "BOM validation against CycloneDX schema failed")
}

func TestCycloneDXSchemaValidation(t *testing.T) {
	schema := compileSchema(t)

	t.Run("empty graph produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("single component produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("multiple components with dependencies produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		compA := cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.2",
			Name:       "express",
			Version:    "4.18.2",
			PackageURL: "pkg:npm/express@4.18.2",
			Type:       cdx.ComponentTypeLibrary,
		}
		compB := cdx.Component{
			BOMRef:     "pkg:npm/body-parser@1.20.2",
			Name:       "body-parser",
			Version:    "1.20.2",
			PackageURL: "pkg:npm/body-parser@1.20.2",
			Type:       cdx.ComponentTypeLibrary,
		}
		compC := cdx.Component{
			BOMRef:     "pkg:npm/bytes@3.1.2",
			Name:       "bytes",
			Version:    "3.1.2",
			PackageURL: "pkg:npm/bytes@3.1.2",
			Type:       cdx.ComponentTypeLibrary,
		}

		idA := g.AddComponent(compA)
		idB := g.AddComponent(compB)
		idC := g.AddComponent(compC)

		g.AddEdge(infoSourceID, idA)
		g.AddEdge(idA, idB)
		g.AddEdge(idB, idC)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("diamond dependency pattern produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		compA := cdx.Component{
			BOMRef:     "pkg:npm/a@1.0.0",
			Name:       "a",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/a@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compB := cdx.Component{
			BOMRef:     "pkg:npm/b@2.0.0",
			Name:       "b",
			Version:    "2.0.0",
			PackageURL: "pkg:npm/b@2.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compC := cdx.Component{
			BOMRef:     "pkg:npm/c@3.0.0",
			Name:       "c",
			Version:    "3.0.0",
			PackageURL: "pkg:npm/c@3.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		idA := g.AddComponent(compA)
		idB := g.AddComponent(compB)
		idC := g.AddComponent(compC)

		// Diamond: root -> A, root -> B, A -> C, B -> C
		g.AddEdge(infoSourceID, idA)
		g.AddEdge(infoSourceID, idB)
		g.AddEdge(idA, idC)
		g.AddEdge(idB, idC)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("components with licenses produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		licenses := cdx.Licenses{
			{License: &cdx.License{ID: "MIT"}},
		}
		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
			Licenses:   &licenses,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("components with hashes produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		hashes := []cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		}
		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
			Hashes:     &hashes,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("BOM with vulnerabilities produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.20",
			Name:       "lodash",
			Version:    "4.17.20",
			PackageURL: "pkg:npm/lodash@4.17.20",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		// Add vulnerability
		affects := []cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}}
		vuln := cdx.Vulnerability{
			ID: "CVE-2021-23337",
			Source: &cdx.Source{
				Name: "NVD",
				URL:  "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
			},
			Affects: &affects,
		}
		g.AddVulnerability(vuln)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("BOM with multiple vulnerabilities and ratings produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.20",
			Name:       "lodash",
			Version:    "4.17.20",
			PackageURL: "pkg:npm/lodash@4.17.20",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		// Add vulnerability with ratings
		affects := []cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}}
		score := 7.5
		ratings := []cdx.VulnerabilityRating{
			{
				Score:    &score,
				Severity: cdx.SeverityHigh,
				Method:   cdx.ScoringMethodCVSSv31,
				Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
		}
		vuln := cdx.Vulnerability{
			ID: "CVE-2021-23337",
			Source: &cdx.Source{
				Name: "NVD",
				URL:  "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
			},
			Affects: &affects,
			Ratings: &ratings,
		}
		g.AddVulnerability(vuln)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("BOM with PURL root name produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("pkg:devguard/org/project/asset@main")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "pkg:devguard/org/project/asset@main",
			ArtifactName: "pkg:devguard/org/project/asset@main",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("complex graph with multiple artifacts produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()

		// Create first artifact with its dependencies
		artifact1ID := g.AddArtifact("frontend")
		infoSource1ID := g.AddInfoSource(artifact1ID, "npm-audit", InfoSourceSBOM)

		compReact := cdx.Component{
			BOMRef:     "pkg:npm/react@18.2.0",
			Name:       "react",
			Version:    "18.2.0",
			PackageURL: "pkg:npm/react@18.2.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compReactDOM := cdx.Component{
			BOMRef:     "pkg:npm/react-dom@18.2.0",
			Name:       "react-dom",
			Version:    "18.2.0",
			PackageURL: "pkg:npm/react-dom@18.2.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		idReact := g.AddComponent(compReact)
		idReactDOM := g.AddComponent(compReactDOM)

		g.AddEdge(infoSource1ID, idReact)
		g.AddEdge(infoSource1ID, idReactDOM)
		g.AddEdge(idReactDOM, idReact) // react-dom depends on react

		// Create second artifact
		artifact2ID := g.AddArtifact("backend")
		infoSource2ID := g.AddInfoSource(artifact2ID, "go-mod", InfoSourceSBOM)

		compGin := cdx.Component{
			BOMRef:     "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			Name:       "github.com/gin-gonic/gin",
			Version:    "v1.9.1",
			PackageURL: "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			Type:       cdx.ComponentTypeLibrary,
		}

		idGin := g.AddComponent(compGin)
		g.AddEdge(infoSource2ID, idGin)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-monorepo",
			ArtifactName: "my-monorepo",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("BOM round-trip produces valid CycloneDX", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.2",
			Name:       "express",
			Version:    "4.18.2",
			PackageURL: "pkg:npm/express@4.18.2",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		// Generate BOM
		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Encode to JSON
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		err := encoder.Encode(bom)
		require.NoError(t, err)

		// Decode back
		var decodedBOM cdx.BOM
		decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
		err = decoder.Decode(&decodedBOM)
		require.NoError(t, err)

		// Validate decoded BOM against schema
		validateBOMAgainstSchema(t, &decodedBOM, schema)
	})
}
