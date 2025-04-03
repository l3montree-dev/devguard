package integrations_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRenderPathToComponent(t *testing.T) {
	t.Run("Everythings works as expected with empty lists", func(t *testing.T) {

		components := []models.ComponentDependency{}
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		result, err := integrations.RenderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err != nil {
			t.Fail()
		}
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'dark' } }%%\n flowchart LR\nroot\n```\n", result)

	})
	t.Run("LoadPathToComponent fails somehow should return an error", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, fmt.Errorf("Something went wrong"))

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		_, err := integrations.RenderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("Everything works as expeted with a non empty component list", func(t *testing.T) {
		components := []models.ComponentDependency{
			{ComponentPurl: utils.Ptr("testPURL"), DependencyPurl: "testDependency"},
			{ComponentPurl: utils.Ptr("testomatL"), DependencyPurl: "testPURL"},
			{ComponentPurl: utils.Ptr("testDependency"), DependencyPurl: "testPURL"},
		}
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		result, err := integrations.RenderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err != nil {
			t.Fail()
		}

		//String for the empty graph + 1 node being root with a linebreak
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'dark' } }%%\n flowchart LR\nroot\n```\n", result)

	})
}

func TestFormatNode(t *testing.T) {
	t.Run("Empty String should also return an empty string back", func(t *testing.T) {
		inputString := ""
		result := integrations.FormatNode(inputString)
		assert.Equal(t, "", result)
	})
	t.Run("Should change nothing when there are less than 2 slashes in the input string", func(t *testing.T) {
		inputString := "StringWIthOnlyOne/"
		result := integrations.FormatNode(inputString)
		assert.Equal(t, inputString, result)
	})
	t.Run("Should put a line break behind the second slash", func(t *testing.T) {
		inputString := "StringWIthOnlyOne//"
		result := integrations.FormatNode(inputString)
		assert.Equal(t, "StringWIthOnlyOne//\n", result)
	})
	t.Run("Should put a line break behind every second slash", func(t *testing.T) {
		inputString := "StringWIthOnlyOne//moreText/newText/nowTHefinalTextChallenge//"
		result := integrations.FormatNode(inputString)
		assert.Equal(t, "StringWIthOnlyOne//\nmoreText/newText/\nnowTHefinalTextChallenge//\n", result)
	})
}
