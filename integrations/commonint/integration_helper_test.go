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
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "pkg:npm:test"

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, artifacts, pURL)
		if err != nil {
			t.Fail()
		}
		// With empty components, the pURL is not reachable, so we get empty string
		assert.Equal(t, "", result)

	})
	t.Run("LoadPathToComponent fails somehow should return an error", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, fmt.Errorf("Something went wrong"))

		assetID := uuid.New()
		assetVersionName := "TestName"
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "pkg:npm:test"

		_, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, artifacts, pURL)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("Everything works as expeted with a non empty component list", func(t *testing.T) {
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "testDependency"}, // root --> testDependency
			{ComponentID: utils.Ptr("testomatL"), DependencyID: "testPURL"},
			{ComponentID: utils.Ptr("testDependency"), DependencyID: "testPURL"},
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "testPURL" // Use a pURL that's actually in the component list

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, artifacts, pURL)
		if err != nil {
			t.Fail()
		}

		//String for the empty graph + 1 node being root with a linebreak
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nroot([\"root\"]) --- testDependency([\"testDependency\"])\ntestDependency([\"testDependency\"]) --- testPURL([\"testPURL\"])\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("should escape @ symbols", func(t *testing.T) {
		components := []models.ComponentDependency{
			{ComponentID: nil, DependencyID: "testDependency"}, // root --> testDependency
			{ComponentID: utils.Ptr("testomatL"), DependencyID: "testPURL"},
			{ComponentID: utils.Ptr("testDependency"), DependencyID: "test@PURL"},
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadComponents", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "test@PURL" // Use a pURL that's actually in the component list

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, artifacts, pURL)
		if err != nil {
			t.Fail()
		}

		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nroot([\"root\"]) --- testDependency([\"testDependency\"])\ntestDependency([\"testDependency\"]) --- test_PURL([\"test\\@PURL\"])\n\nclassDef default stroke-width:2px\n```\n", result)

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
			"source-code",
			"container",
			"container:test",
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
