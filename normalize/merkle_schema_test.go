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

// components builds a components map keyed by PackageURL, as ToCycloneDX
// expects, from a plain list.
func components(comps ...cdx.Component) map[string]cdx.Component {
	out := make(map[string]cdx.Component, len(comps))
	for _, c := range comps {
		out[c.PackageURL] = c
	}
	return out
}

func TestCycloneDXSchemaValidation(t *testing.T) {
	schema := compileSchema(t)

	t.Run("empty tree produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, nil)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("single component produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/lodash@4.17.21"},
		}, "my-app")

		comps := components(cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
		})

		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("multiple components with dependencies produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot:              {"pkg:npm/express@4.18.2"},
			"pkg:npm/express@4.18.2":     {"pkg:npm/body-parser@1.20.2"},
			"pkg:npm/body-parser@1.20.2": {"pkg:npm/bytes@3.1.2"},
		}, "my-app")

		comps := components(
			cdx.Component{BOMRef: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", PackageURL: "pkg:npm/express@4.18.2", Type: cdx.ComponentTypeLibrary},
			cdx.Component{BOMRef: "pkg:npm/body-parser@1.20.2", Name: "body-parser", Version: "1.20.2", PackageURL: "pkg:npm/body-parser@1.20.2", Type: cdx.ComponentTypeLibrary},
			cdx.Component{BOMRef: "pkg:npm/bytes@3.1.2", Name: "bytes", Version: "3.1.2", PackageURL: "pkg:npm/bytes@3.1.2", Type: cdx.ComponentTypeLibrary},
		)

		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("diamond dependency pattern produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot:   {"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/c@3.0.0"},
			"pkg:npm/b@2.0.0": {"pkg:npm/c@3.0.0"},
		}, "my-app")

		comps := components(
			cdx.Component{BOMRef: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", PackageURL: "pkg:npm/a@1.0.0", Type: cdx.ComponentTypeLibrary},
			cdx.Component{BOMRef: "pkg:npm/b@2.0.0", Name: "b", Version: "2.0.0", PackageURL: "pkg:npm/b@2.0.0", Type: cdx.ComponentTypeLibrary},
			cdx.Component{BOMRef: "pkg:npm/c@3.0.0", Name: "c", Version: "3.0.0", PackageURL: "pkg:npm/c@3.0.0", Type: cdx.ComponentTypeLibrary},
		)

		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("components with licenses produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/lodash@4.17.21"},
		}, "my-app")

		licenses := cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}
		comps := components(cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
			Licenses:   &licenses,
		})

		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("components with hashes produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/lodash@4.17.21"},
		}, "my-app")

		hashes := []cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		}
		comps := components(cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
			Hashes:     &hashes,
		})

		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("VEX with vulnerabilities produces valid CycloneDX", func(t *testing.T) {
		affects := []cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}}
		vuln := cdx.Vulnerability{
			ID:      "CVE-2021-23337",
			Source:  &cdx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
			Affects: &affects,
		}

		bom := CycloneDXVEXFromVulnerabilities([]cdx.Vulnerability{vuln}, BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("VEX with multiple vulnerabilities and ratings produces valid CycloneDX", func(t *testing.T) {
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
			ID:      "CVE-2021-23337",
			Source:  &cdx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
			Affects: &affects,
			Ratings: &ratings,
		}

		bom := CycloneDXVEXFromVulnerabilities([]cdx.Vulnerability{vuln}, BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("BOM with PURL root name produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/lodash@4.17.21"},
		}, "pkg:devguard/org/project/asset@main")

		comps := components(cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
		})

		bom := tree.ToCycloneDX(BOMMetadata{
			RootName:     "pkg:devguard/org/project/asset@main",
			ArtifactName: "pkg:devguard/org/project/asset@main",
		}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("complex forest with multiple artifacts produces valid CycloneDX", func(t *testing.T) {
		frontend := buildTree(map[string][]string{
			merkleParseRoot:            {"pkg:npm/react@18.2.0", "pkg:npm/react-dom@18.2.0"},
			"pkg:npm/react-dom@18.2.0": {"pkg:npm/react@18.2.0"},
		}, "frontend")
		backend := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:golang/github.com/gin-gonic/gin@v1.9.1"},
		}, "backend")

		comps := components(
			cdx.Component{BOMRef: "pkg:npm/react@18.2.0", Name: "react", Version: "18.2.0", PackageURL: "pkg:npm/react@18.2.0", Type: cdx.ComponentTypeLibrary},
			cdx.Component{BOMRef: "pkg:npm/react-dom@18.2.0", Name: "react-dom", Version: "18.2.0", PackageURL: "pkg:npm/react-dom@18.2.0", Type: cdx.ComponentTypeLibrary},
			cdx.Component{BOMRef: "pkg:golang/github.com/gin-gonic/gin@v1.9.1", Name: "github.com/gin-gonic/gin", Version: "v1.9.1", PackageURL: "pkg:golang/github.com/gin-gonic/gin@v1.9.1", Type: cdx.ComponentTypeLibrary},
		)

		bom := MerkleForest{frontend, backend}.ToCycloneDX(BOMMetadata{
			RootName:     "my-monorepo",
			ArtifactName: "my-monorepo",
		}, comps)

		validateBOMAgainstSchema(t, bom, schema)
	})

	t.Run("BOM round-trip produces valid CycloneDX", func(t *testing.T) {
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/express@4.18.2"},
		}, "my-app")

		comps := components(cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.2",
			Name:       "express",
			Version:    "4.18.2",
			PackageURL: "pkg:npm/express@4.18.2",
			Type:       cdx.ComponentTypeLibrary,
		})

		// Generate BOM
		bom := tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, comps)

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
