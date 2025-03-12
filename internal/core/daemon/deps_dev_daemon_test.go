package daemon

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/mock"
)

func TestHandleComponent(t *testing.T) {
	mockDepsDevService := mocks.NewCoreDepsDevService(t)
	mockComponentProjectRepository := mocks.NewCoreComponentProjectRepository(t)
	mockComponentRepository := mocks.NewCoreComponentRepository(t)

	t.Run("should set the license to unknown, if there is no license information", func(t *testing.T) {
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

}
