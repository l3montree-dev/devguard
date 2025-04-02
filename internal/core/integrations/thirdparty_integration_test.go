package integrations_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
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

		_, err := integrations.RenderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err != nil {
			t.Fail()
		}

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
			models.ComponentDependency{ComponentPurl: utils.Ptr("testPURL"), DependencyPurl: "testDependency"},
			models.ComponentDependency{ComponentPurl: utils.Ptr("testomatL"), DependencyPurl: "testPURL"},
			models.ComponentDependency{ComponentPurl: utils.Ptr("testDependency"), DependencyPurl: "testPURL"},
		}
		componentRepository := mocks.NewCoreComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(components, nil)

		assetID := uuid.New()
		assetVersionName := "TestName"
		scannerID := "SBOM-File-Upload"
		pURL := "pkg:npm:test"

		_, err := integrations.RenderPathToComponent(componentRepository, assetID, assetVersionName, scannerID, pURL)
		if err != nil {
			t.Fail()
		}

	})
}
