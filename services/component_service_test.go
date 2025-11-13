package services

import (
	"fmt"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleComponent(t *testing.T) {
	t.Run("should set the license to unknown, if there is no license information", func(t *testing.T) {
		mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
		mockComponentProjectRepository := mocks.NewComponentProjectRepository(t)
		mockComponentRepository := mocks.NewComponentRepository(t)
		mockLicenseRiskService := mocks.NewLicenseRiskService(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		service := services.NewComponentService(mockOpenSourceInsightService, mockComponentProjectRepository, mockComponentRepository, mockLicenseRiskService, mockArtifactRepository, utils.NewSyncFireAndForgetSynchronizer())

		component := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: nil,
		}

		mockOpenSourceInsightService.On("GetVersion", mock.Anything, "golang", "gorm.io/gorm", "v1.25.12").Return(common.OpenSourceInsightsVersionResponse{}, nil)

		actual, err := service.GetLicense(component)

		assert.NoError(t, err)
		assert.Equal(t, utils.Ptr("unknown"), actual.License)
	})
	t.Run("should also get alpine Licenses", func(t *testing.T) {
		mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
		mockComponentProjectRepository := mocks.NewComponentProjectRepository(t)
		mockComponentRepository := mocks.NewComponentRepository(t)
		mockLicenseRiskService := mocks.NewLicenseRiskService(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		service := services.NewComponentService(mockOpenSourceInsightService, mockComponentProjectRepository, mockComponentRepository, mockLicenseRiskService, mockArtifactRepository, utils.NewSyncFireAndForgetSynchronizer())

		component := models.Component{
			Purl:    "pkg:apk/alpine/abiword-plugin-collab@3.0.0-r4",
			Version: "3.0.0-r4",
			License: nil,
		}

		actual, err := service.GetLicense(component)
		fmt.Printf("License %s", *actual.License)
		assert.NoError(t, err)
		assert.NotEqual(t, utils.Ptr("unknown"), actual.License)
	})

	t.Run("should find debian licenses", func(t *testing.T) {
		mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
		mockComponentProjectRepository := mocks.NewComponentProjectRepository(t)
		mockComponentRepository := mocks.NewComponentRepository(t)
		mockLicenseRiskService := mocks.NewLicenseRiskService(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		service := services.NewComponentService(mockOpenSourceInsightService, mockComponentProjectRepository, mockComponentRepository, mockLicenseRiskService, mockArtifactRepository, utils.NewSyncFireAndForgetSynchronizer())
		component := models.Component{
			Purl:    "pkg:deb/debian/gdbm@1.23", // that is how the component looks - the version inside the purl is not the full version
			Version: "1.23-3",
			License: nil,
		}

		actual, err := service.GetLicense(component)

		assert.NoError(t, err)
		assert.NotEqual(t, utils.Ptr("unknown"), actual.License)
	})

	t.Run("should set the license information to unknown, if there is an error in the deps dev service", func(t *testing.T) {
		mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
		mockComponentProjectRepository := mocks.NewComponentProjectRepository(t)
		mockComponentRepository := mocks.NewComponentRepository(t)
		mockLicenseRiskService := mocks.NewLicenseRiskService(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		c := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: nil,
		}

		mockOpenSourceInsightService.On("GetVersion", mock.Anything, "golang", "gorm.io/gorm", "v1.25.12").Return(common.OpenSourceInsightsVersionResponse{}, assert.AnError)
		service := services.NewComponentService(mockOpenSourceInsightService, mockComponentProjectRepository, mockComponentRepository, mockLicenseRiskService, mockArtifactRepository, utils.NewSyncFireAndForgetSynchronizer())

		actual, err := service.GetLicense(c)

		assert.NoError(t, err)

		assert.Equal(t, utils.Ptr("unknown"), actual.License)
	})

	t.Run("should fetch the project information if there is a SOURCE_REPO defined in the related projects", func(t *testing.T) {
		mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
		mockComponentProjectRepository := mocks.NewComponentProjectRepository(t)
		mockComponentRepository := mocks.NewComponentRepository(t)
		mockLicenseRiskService := mocks.NewLicenseRiskService(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		c := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: nil,
		}

		mockOpenSourceInsightService.On("GetVersion", mock.Anything, "golang", "gorm.io/gorm", "v1.25.12").Return(common.OpenSourceInsightsVersionResponse{
			RelatedProjects: []struct {
				ProjectKey struct {
					ID string "json:\"id\""
				} "json:\"projectKey\""
				RelationProvenance string "json:\"relationProvenance\""
				RelationType       string "json:\"relationType\""
			}{
				{
					ProjectKey: struct {
						ID string "json:\"id\""
					}{ID: "github/test/project"},
					RelationType: "SOURCE_REPO",
				},
			},
		}, nil)

		projectResponse := common.OpenSourceInsightsProjectResponse{
			ProjectKey: struct {
				ID string "json:\"id\""
			}{ID: "github/test/project"},
		}
		mockOpenSourceInsightService.On("GetProject", mock.Anything, "github/test/project").Return(projectResponse, nil)

		service := services.NewComponentService(mockOpenSourceInsightService, mockComponentProjectRepository, mockComponentRepository, mockLicenseRiskService, mockArtifactRepository, utils.NewSyncFireAndForgetSynchronizer())

		actual, err := service.GetLicense(c)

		assert.NoError(t, err)
		assert.Equal(t, utils.Ptr("github/test/project"), actual.ComponentProjectKey)
	})
}

func TestHandleProject(t *testing.T) {
	t.Run("should save the project information", func(t *testing.T) {
		mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
		mockComponentProjectRepository := mocks.NewComponentProjectRepository(t)
		mockLicenseRiskService := mocks.NewLicenseRiskService(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		project := models.ComponentProject{
			ProjectKey: "github/test/project",
		}

		var scoreCard = common.Scorecard{
			Date: time.Now(),
			Repository: struct {
				Name   string "json:\"name\""
				Commit string "json:\"commit\""
			}{
				Name:   "test",
				Commit: "123",
			},
			Scorecard: struct {
				Version string "json:\"version\""
				Commit  string "json:\"commit\""
			}{
				Version: "1.0.0",
				Commit:  "123",
			},
		}

		jsonB := database.MustJSONBFromStruct(scoreCard)
		expectedProject := models.ComponentProject{
			ProjectKey:  "github/test/project",
			ScoreCard:   &jsonB,
			Description: "A test project",
			License:     "MIT",
		}

		projectResponse := common.OpenSourceInsightsProjectResponse{
			ProjectKey: struct {
				ID string "json:\"id\""
			}{ID: "github/test/project"},
			License:     "MIT",
			Description: "A test project",
			Homepage:    "",
			Scorecard:   &scoreCard,
		}

		mockOpenSourceInsightService.On("GetProject", mock.Anything, "github/test/project").Return(projectResponse, nil)

		mockComponentProjectRepository.On("Save", mock.Anything, &expectedProject).Return(nil)

		service := services.NewComponentService(mockOpenSourceInsightService, mockComponentProjectRepository, nil, mockLicenseRiskService, mockArtifactRepository, utils.NewSyncFireAndForgetSynchronizer())
		service.RefreshComponentProjectInformation(project)
	})
}
