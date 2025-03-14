package daemon

import (
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleComponent(t *testing.T) {

	t.Run("should set the license to unknown, if there is no license information", func(t *testing.T) {
		mockDepsDevService := mocks.NewCoreDepsDevService(t)
		mockComponentProjectRepository := mocks.NewCoreComponentProjectRepository(t)
		mockComponentRepository := mocks.NewCoreComponentRepository(t)

		component := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: nil,
		}

		expected := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: utils.Ptr("unknown"),
		}

		mockDepsDevService.On("GetVersion", mock.Anything, "golang", "gorm.io/gorm", "v1.25.12").Return(common.DepsDevVersionResponse{}, nil)

		mockComponentRepository.On("Save", mock.Anything, &expected).Return(nil)
		handleComponent(mockDepsDevService, mockComponentProjectRepository, mockComponentRepository, component)
	})

	t.Run("should set the license information to unknown, if there is an error in the deps dev daemon", func(t *testing.T) {
		mockDepsDevService := mocks.NewCoreDepsDevService(t)
		mockComponentProjectRepository := mocks.NewCoreComponentProjectRepository(t)
		mockComponentRepository := mocks.NewCoreComponentRepository(t)

		component := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: nil,
		}

		expected := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: utils.Ptr("unknown"),
		}

		mockDepsDevService.On("GetVersion", mock.Anything, "golang", "gorm.io/gorm", "v1.25.12").Return(common.DepsDevVersionResponse{}, assert.AnError)

		mockComponentRepository.On("Save", mock.Anything, &expected).Return(nil)
		handleComponent(mockDepsDevService, mockComponentProjectRepository, mockComponentRepository, component)
	})

	t.Run("should fetch the project information if there is a SOURCE_REPO defined in the related projects", func(t *testing.T) {
		mockDepsDevService := mocks.NewCoreDepsDevService(t)
		mockComponentProjectRepository := mocks.NewCoreComponentProjectRepository(t)
		mockComponentRepository := mocks.NewCoreComponentRepository(t)

		component := models.Component{
			Purl:    "pkg:golang/gorm.io/gorm@v1.25.12",
			Version: "v1.0.0",
			License: nil,
		}

		expected := models.Component{
			Purl:               "pkg:golang/gorm.io/gorm@v1.25.12",
			Version:            "v1.0.0",
			License:            utils.Ptr("unknown"),
			ComponentProjectID: utils.Ptr("github/test/project"),
		}

		mockDepsDevService.On("GetVersion", mock.Anything, "golang", "gorm.io/gorm", "v1.25.12").Return(common.DepsDevVersionResponse{
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

		projectResponse := common.DepsDevProjectResponse{
			ProjectKey: struct {
				ID string "json:\"id\""
			}{ID: "github/test/project"},
		}
		mockDepsDevService.On("GetProject", mock.Anything, "github/test/project").Return(projectResponse, nil)

		mockComponentProjectRepository.On("Save", mock.Anything, &models.ComponentProject{
			ID:        "github/test/project",
			ScoreCard: database.MustJsonBFromStruct(projectResponse.Scorecard),
		}).Return(nil)

		mockComponentRepository.On("Save", mock.Anything, &expected).Return(nil)
		handleComponent(mockDepsDevService, mockComponentProjectRepository, mockComponentRepository, component)
	})
}

func TestHandleProject(t *testing.T) {
	t.Run("should save the project information", func(t *testing.T) {
		mockDepsDevService := mocks.NewCoreDepsDevService(t)
		mockComponentProjectRepository := mocks.NewCoreComponentProjectRepository(t)

		project := models.ComponentProject{
			ID: "github/test/project",
		}

		var scoreCard common.Scorecard = common.Scorecard{
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

		expectedProject := models.ComponentProject{
			ID:          "github/test/project",
			ScoreCard:   database.MustJsonBFromStruct(scoreCard),
			Description: "A test project",
			License:     "MIT",
		}

		projectResponse := common.DepsDevProjectResponse{
			ProjectKey: struct {
				ID string "json:\"id\""
			}{ID: "github/test/project"},
			License:     "MIT",
			Description: "A test project",
			Homepage:    "",
			Scorecard:   scoreCard,
		}

		mockDepsDevService.On("GetProject", mock.Anything, "github/test/project").Return(projectResponse, nil)

		mockComponentProjectRepository.On("Save", mock.Anything, &expectedProject).Return(nil)
		handleComponentProject(mockDepsDevService, mockComponentProjectRepository, project)

	})
}
