package scan

import (
	"fmt"
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/mock"
)

func TestShouldCreateIssue(t *testing.T) {
	t.Run("Function should return nil if we are not on the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: false,
		}
		asset := models.Asset{}
		err := ShouldCreateIssue(nil, asset, assetVersion, nil)
		if err != nil {
			t.Fail()
		}
	})
	t.Run("Function should return nil if we successfully create an issue", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: true,
		}
		asset := models.Asset{}
		vulns := []models.DependencyVuln{}

		dependencyVulnRepositoryMock := mocks.NewCoreDependencyVulnService(t)
		dependencyVulnRepositoryMock.On("CreateIssuesForVulns", mock.Anything, mock.Anything).Return(nil)

		controller := NewHttpController(nil, nil, nil, nil, nil, nil, nil, dependencyVulnRepositoryMock)

		err := ShouldCreateIssue(controller, asset, assetVersion, vulns)
		if err != nil {
			t.Fail()
		}
	})
	t.Run("Function should return an error if we run into problems when creating the issue", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: true,
		}
		asset := models.Asset{}
		vulns := []models.DependencyVuln{}

		dependencyVulnRepositoryMock := mocks.NewCoreDependencyVulnService(t)
		dependencyVulnRepositoryMock.On("CreateIssuesForVulns", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong when creating the Issue"))

		controller := NewHttpController(nil, nil, nil, nil, nil, nil, nil, dependencyVulnRepositoryMock)

		err := ShouldCreateIssue(controller, asset, assetVersion, vulns)
		if err == nil {
			t.Fail()
		}
	})
}
