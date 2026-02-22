package commonint

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gosimple/slug"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRenderPathToComponent(t *testing.T) {
	t.Run("Everything works as expected with empty lists", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm:test"

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err != nil {
			t.Fail()
		}
		// With empty components, the pURL is not reachable, so we get empty mermaid diagram
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("LoadPathToComponent fails somehow should return an error", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, fmt.Errorf("Something went wrong"))

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm:test"

		_, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("Everything works as expeted with a non empty component list", func(t *testing.T) {
		// Create a chain of actual components (all with pkg: prefix) to have a path with edges
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "artifact:test-artifact", Dependency: models.Component{ID: "artifact:test-artifact"}},                                         // root --> artifact
			{ComponentID: utils.Ptr("artifact:test-artifact"), DependencyID: "sbom:test@test-artifact", Dependency: models.Component{ID: "sbom:test@test-artifact"}},       // artifact -> sbom
			{ComponentID: utils.Ptr("sbom:test@test-artifact"), DependencyID: "pkg:npm/root-dep@1.0.0", Dependency: models.Component{ID: "pkg:npm/root-dep@1.0.0"}},        // sbom -> root-dep (component)
			{ComponentID: utils.Ptr("pkg:npm/root-dep@1.0.0"), DependencyID: "pkg:npm/test-package@1.0.0", Dependency: models.Component{ID: "pkg:npm/test-package@1.0.0"}}, // root-dep -> test-package (component)
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		pURL := "pkg:npm/test-package@1.0.0" // Use a pURL that's actually in the component list

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err != nil {
			t.Fail()
		}

		// FindAllComponentOnlyPathsToPURL only returns component-only paths (nodes starting with pkg:)
		// The path should be: root-dep -> test-package
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\npkg_npm_root_dep_1_0_0([\"pkg:npm/root-dep\\@1.0.0\"]) --- pkg_npm_test_package_1_0_0([\"pkg:npm/test-package\\@1.0.0\"])\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("should escape @ symbols", func(t *testing.T) {
		// Create a chain of actual components to verify @ escaping in mermaid output
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "artifact:test-artifact", Dependency: models.Component{ID: "artifact:test-artifact"}},                                         // root --> artifact
			{ComponentID: utils.Ptr("artifact:test-artifact"), DependencyID: "sbom:test@test-artifact", Dependency: models.Component{ID: "sbom:test@test-artifact"}},       // artifact -> sbom
			{ComponentID: utils.Ptr("sbom:test@test-artifact"), DependencyID: "pkg:npm/root-dep@1.0.0", Dependency: models.Component{ID: "pkg:npm/root-dep@1.0.0"}},        // sbom -> root-dep (component)
			{ComponentID: utils.Ptr("pkg:npm/root-dep@1.0.0"), DependencyID: "pkg:npm/test-package@1.0.0", Dependency: models.Component{ID: "pkg:npm/test-package@1.0.0"}}, // root-dep -> test-package (component)
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"

		pURL := "pkg:npm/test-package@1.0.0" // Use a pURL that's actually in the component list

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, pURL)
		if err != nil {
			t.Fail()
		}

		// Verify @ symbols are escaped as \@ in the mermaid output
		assert.Contains(t, result, "\\@1.0.0")
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\npkg_npm_root_dep_1_0_0([\"pkg:npm/root-dep\\@1.0.0\"]) --- pkg_npm_test_package_1_0_0([\"pkg:npm/test-package\\@1.0.0\"])\n\nclassDef default stroke-width:2px\n```\n", result)

	})
}
func TestGetLabels(t *testing.T) {
	t.Run("should return correct labels for a DependencyVuln with CVE", func(t *testing.T) {
		vuln := &models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: dtos.VulnStateOpen,
			},
			Artifacts: []models.Artifact{
				{ArtifactName: "source-code"},
				{ArtifactName: "container"},
				{ArtifactName: "container:test"},
				{ArtifactName: "source-code:test"},
			},
			RawRiskAssessment: utils.Ptr(0.2),
		}
		expectedLabels := []string{
			"devguard",
			"state:open",
			"risk:low",
			"container",
			"container:test",
			"source-code",
			"source-code:test",
		}

		assert.Equal(t, expectedLabels, GetLabels(vuln))
	})

	t.Run("should return correct labels for a FirstPartyVuln", func(t *testing.T) {
		vuln := &models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				State: dtos.VulnStateFixed,
			},
			ScannerIDs: "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sast github.com/l3montree-dev/devguard/cmd/devguard-scanner/secret-scanning github.com/l3montree-dev/devguard/cmd/devguard-scanner/iac",
		}

		expectedLabels := []string{
			"devguard",
			"state:fixed",
			"sast",
			"secret-scanning",
			"iac",
		}

		assert.Equal(t, expectedLabels, GetLabels(vuln))
	})

}

func TestBuildGitlabCiTemplate(t *testing.T) {

	t.Run("should build full template with default environment variables", func(t *testing.T) {
		// Clear environment variables to test defaults
		os.Unsetenv("DEVGUARD_CI_COMPONENT_BASE")
		os.Unsetenv("FRONTEND_URL")

		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		assert.Contains(t, result, "stages:")
		assert.Contains(t, result, "- test")
		assert.Contains(t, result, "- oci-image")
		assert.Contains(t, result, "- attestation")
		assert.Contains(t, result, "include:")
		assert.Contains(t, result, "remote: \"https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"app.devguard.org\"")
		assert.Contains(t, result, "asset_name: \"$DEVGUARD_ASSET_NAME\"")
		assert.Contains(t, result, "token: \"$DEVGUARD_TOKEN\"")
		assert.Contains(t, result, "api_url: \"$DEVGUARD_API_URL\"")
	})

	t.Run("should build full template with custom environment variables", func(t *testing.T) {
		// Set custom environment variables
		os.Setenv("DEVGUARD_CI_COMPONENT_BASE", "https://custom.gitlab.com/devguard/-/raw/main")
		os.Setenv("FRONTEND_URL", "custom.devguard.example.com")
		defer func() {
			os.Unsetenv("DEVGUARD_CI_COMPONENT_BASE")
			os.Unsetenv("FRONTEND_URL")
		}()

		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		assert.Contains(t, result, "remote: \"https://custom.gitlab.com/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"custom.devguard.example.com\"")
	})

	t.Run("should handle empty environment variables and use defaults", func(t *testing.T) {
		// Set empty environment variables
		os.Setenv("DEVGUARD_CI_COMPONENT_BASE", "")
		os.Setenv("FRONTEND_URL", "")
		defer func() {
			os.Unsetenv("DEVGUARD_CI_COMPONENT_BASE")
			os.Unsetenv("FRONTEND_URL")
		}()

		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		assert.Contains(t, result, "remote: \"https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"app.devguard.org\"")
	})

	t.Run("should NOT return error for unknown template ID", func(t *testing.T) {
		result, err := buildGitlabCiTemplate("unknown")

		assert.Nil(t, err)

		// defaults to full
		assert.Contains(t, result, "stages:")
		assert.Contains(t, result, "- test")
		assert.Contains(t, result, "- oci-image")
		assert.Contains(t, result, "- attestation")
		assert.Contains(t, result, "include:")
		assert.Contains(t, result, "remote: \"https://gitlab.com/l3montree/devguard/-/raw/main/templates/full.yml\"")
		assert.Contains(t, result, "web_ui: \"app.devguard.org\"")
	})

	t.Run("should generate valid YAML structure", func(t *testing.T) {
		result, err := buildGitlabCiTemplate("full")

		assert.NoError(t, err)
		// Verify basic YAML structure
		lines := strings.Split(result, "\n")
		assert.True(t, len(lines) > 0)

		// Check that stages section exists and is properly formatted
		hasStages := false
		hasInclude := false
		for _, line := range lines {
			if strings.TrimSpace(line) == "stages:" {
				hasStages = true
			}
			if strings.TrimSpace(line) == "include:" {
				hasInclude = true
			}
		}
		assert.True(t, hasStages, "Template should contain stages section")
		assert.True(t, hasInclude, "Template should contain include section")
	})
}

func TestRenderMarkdown(t *testing.T) {

	baseURL := "https://devguard.example.com"
	orgSlug := "my-org"
	projectSlug := "my-project"
	assetSlug := "my-asset"
	assetVersionName := "v1.0.0"

	assertVersionSlug := slug.Make(assetVersionName)
	assert.Equal(t, "v1-0-0", assertVersionSlug)

	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		snippetContents := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{
				{
					StartLine:   64,
					EndLine:     64,
					StartColumn: 1,
					EndColumn:   20,
					Snippet:     "TestSnippet",
				},
			},
		}
		snippetJSON, err := transformer.SnippetContentsToJSON(snippetContents)
		assert.NoError(t, err)

		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: snippetJSON,
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message"),
				ID: "test-vuln-id",
			},
			URI: "the/uri/of/the/vuln",
		}
		result := RenderMarkdownForFirstPartyVuln(firstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug)
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "TestSnippet")
		assert.Contains(t, result, "**Found at:** [the/uri/of/the/vuln](../the/uri/of/the/vuln#L64)")
		assert.Contains(t, result, fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/code-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug, firstPartyVuln.ID))
	})
	t.Run("vuln without snippet contents", func(t *testing.T) {
		snippetContents := dtos.SnippetContents{
			Snippets: []dtos.SnippetContent{
				{},
			},
		}
		snippetJSON, err := transformer.SnippetContentsToJSON(snippetContents)
		assert.NoError(t, err)
		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: snippetJSON,
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message"),
				ID: "test-vuln-id"},
			URI: "the/uri/of/the/vuln",
		}

		result := RenderMarkdownForFirstPartyVuln(firstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug)
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "**Found at:** [the/uri/of/the/vuln](../the/uri/of/the/vuln#L0)")
		assert.Contains(t, result, fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/code-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug, firstPartyVuln.ID))
	})
}

// TestTicketContentBitwiseReproducibility proves that GitLab ticket content
// (labels and Mermaid path diagrams) is identical byte-for-byte across runs,
// regardless of the order in which artifacts or components are provided.
func TestTicketContentBitwiseReproducibility(t *testing.T) {
	t.Run("GetLabels produces identical output regardless of artifact slice order", func(t *testing.T) {
		artifacts := []models.Artifact{
			{ArtifactName: "source-code"},
			{ArtifactName: "container"},
			{ArtifactName: "binary"},
		}

		// Three permutations of the same artifact set
		orders := [][]models.Artifact{
			{artifacts[0], artifacts[1], artifacts[2]},
			{artifacts[2], artifacts[0], artifacts[1]},
			{artifacts[1], artifacts[2], artifacts[0]},
		}

		var reference []string
		for i, order := range orders {
			vuln := &models.DependencyVuln{
				Vulnerability:     models.Vulnerability{State: dtos.VulnStateOpen},
				Artifacts:         order,
				RawRiskAssessment: utils.Ptr(0.5),
			}
			labels := GetLabels(vuln)
			if i == 0 {
				reference = labels
			} else {
				assert.Equal(t, reference, labels, "labels differ for artifact permutation %d", i)
			}
		}
	})

	t.Run("RenderPathToComponent produces identical Mermaid output across repeated calls", func(t *testing.T) {
		// Graph: sbom → route-b and route-a (intentionally "wrong" alphabetical order in slice)
		// both routes lead to the target, producing two component-only paths.
		// Previously, map iteration randomness caused the two path edges to appear
		// in non-deterministic order in the Mermaid output.
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "artifact:art", Dependency: models.Component{ID: "artifact:art"}},
			{ComponentID: utils.Ptr("artifact:art"), DependencyID: "sbom:s@art", Dependency: models.Component{ID: "sbom:s@art"}},
			{ComponentID: utils.Ptr("sbom:s@art"), DependencyID: "pkg:npm/route-b@1.0", Dependency: models.Component{ID: "pkg:npm/route-b@1.0"}},
			{ComponentID: utils.Ptr("sbom:s@art"), DependencyID: "pkg:npm/route-a@1.0", Dependency: models.Component{ID: "pkg:npm/route-a@1.0"}},
			{ComponentID: utils.Ptr("pkg:npm/route-a@1.0"), DependencyID: "pkg:npm/target@1.0", Dependency: models.Component{ID: "pkg:npm/target@1.0"}},
			{ComponentID: utils.Ptr("pkg:npm/route-b@1.0"), DependencyID: "pkg:npm/target@1.0", Dependency: models.Component{ID: "pkg:npm/target@1.0"}},
		}

		assetID := uuid.New()
		pURL := "pkg:npm/target@1.0"

		// Run 50 times — enough to surface any map-iteration randomness.
		const runs = 50
		results := make([]string, runs)
		for i := range runs {
			repo := mocks.NewComponentRepository(t)
			repo.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)
			result, err := RenderPathToComponent(repo, assetID, "v1.0.0", pURL)
			assert.NoError(t, err)
			results[i] = result
		}

		for i := 1; i < runs; i++ {
			assert.Equal(t, results[0], results[i], "Mermaid output differed on run %d", i)
		}

		// Also verify route-a edges appear before route-b edges (alphabetical DFS order).
		assert.Less(t,
			strings.Index(results[0], "route-a"),
			strings.Index(results[0], "route-b"),
			"route-a should appear before route-b in sorted DFS output",
		)
	})
}
