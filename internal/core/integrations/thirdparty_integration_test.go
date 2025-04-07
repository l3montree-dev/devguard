package integrations

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
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		result, err := renderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err != nil {
			t.Fail()
		}
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'dark' } }%%\n flowchart TD\nroot\n```\n", result)

	})
	t.Run("LoadPathToComponent fails somehow should return an error", func(t *testing.T) {
		components := []models.ComponentDependency{}
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, fmt.Errorf("Something went wrong"))

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		_, err := renderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("Everything works as expeted with a non empty component list", func(t *testing.T) {
		components := []models.ComponentDependency{
			{ComponentPurl: nil, DependencyPurl: "testDependency"}, // root --> testDependency
			{ComponentPurl: utils.Ptr("testomatL"), DependencyPurl: "testPURL"},
			{ComponentPurl: utils.Ptr("testDependency"), DependencyPurl: "testPURL"},
		}
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		result, err := renderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err != nil {
			t.Fail()
		}

		//String for the empty graph + 1 node being root with a linebreak
		assert.Equal(t, "```mermaid \n %%{init: { 'theme':'dark' } }%%\n flowchart TD\nroot --> \nnode0[testDependency] --> \nnode1[testPURL]\n```\n", result)

	})
}

func TestBeautifyPURL(t *testing.T) {
	t.Run("empty String should also return an empty string back", func(t *testing.T) {
		inputString := ""
		result, _ := beautifyPURL(inputString)
		assert.Equal(t, "", result)
	})
	t.Run("invalid purl format should also be returned unchanged", func(t *testing.T) {
		inputString := "this is definitely not a valid purl"
		result, _ := beautifyPURL(inputString)
		assert.Equal(t, inputString, result)
	})
	t.Run("should return only the namespace and the name of a valid purl and cut the rest", func(t *testing.T) {
		inputString := "pkg:npm/@ory/integrations@v0.0.1"
		result, _ := beautifyPURL(inputString)
		assert.Equal(t, "@ory/integrations", result)
	})
	t.Run("should return no leading slash if the namespace is empty", func(t *testing.T) {
		inputString := "pkg:npm/integrations@v0.0.1"
		result, _ := beautifyPURL(inputString)
		assert.Equal(t, "integrations", result)
	})
}
