package commonint

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRenderPathToComponent(t *testing.T) {
	t.Run("Everything works as expected with empty lists", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "pkg:npm:test"

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, artifacts, pURL)
		if err != nil {
			t.Fail()
		}
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("LoadPathToComponent fails somehow should return an error", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, fmt.Errorf("Something went wrong"))

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
			{ComponentPurl: nil, DependencyPurl: "testDependency", Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}}, // root --> testDependency
			{ComponentPurl: utils.Ptr("testomatL"), DependencyPurl: "testPURL", Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}},
			{ComponentPurl: utils.Ptr("testDependency"), DependencyPurl: "testPURL", Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}},
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "pkg:npm:test"

		result, err := RenderPathToComponent(componentRepository, assetID, assetVersionName, artifacts, pURL)
		if err != nil {
			t.Fail()
		}

		//String for the empty graph + 1 node being root with a linebreak
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nroot([\"root\"]) --- testDependency([\"testDependency\"])\ntestDependency([\"testDependency\"]) --- testPURL([\"testPURL\"])\n\nclassDef default stroke-width:2px\n```\n", result)

	})
	t.Run("should escape @ symbols", func(t *testing.T) {
		components := []models.ComponentDependency{
			{ComponentPurl: nil, DependencyPurl: "testDependency", Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}}, // root --> testDependency
			{ComponentPurl: utils.Ptr("testomatL"), DependencyPurl: "testPURL", Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}},
			{ComponentPurl: utils.Ptr("testDependency"), DependencyPurl: "test@PURL", Artifacts: []models.Artifact{{ArtifactName: "artifact1"}}},
		}
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		artifacts := []models.Artifact{{ArtifactName: "SBOM-File-Upload"}}
		pURL := "pkg:npm:test"

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
				State: models.VulnStateOpen,
			},
			Artifacts: []models.Artifact{
				{ArtifactName: "source-code"},
				{ArtifactName: "container"},
				{ArtifactName: "container:test"},
				{ArtifactName: "source-code:test"},
				{ArtifactName: "sast"},
				{ArtifactName: "secret-scanning"},
				{ArtifactName: "iac"},
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
			"sast",
			"secret-scanning",
			"iac",
		}

		assert.Equal(t, expectedLabels, GetLabels(vuln))
	})

}
