package dependencyVuln_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/mock"
)

func TestCreateIssuesForUpdatedVulns(t *testing.T) {
	t.Run("Default test", func(t *testing.T) {

		asset := models.Asset{
			RiskAutomaticTicketThreshold: utils.Ptr(2.),
		}
		mockIntegrationAggregate := mocks.NewCoreIntegrationAggregate(t)
		mockIntegrationAggregate.On("CreateIssue", mock.Anything).Return(nil)

		err := dependencyVuln.CreateIssuesForUpdatedVulns(nil, mockIntegrationAggregate, asset, []models.DependencyVuln{
			{
				RawRiskAssessment: utils.Ptr(2.),
			},
		})

		if err != nil {
			t.Fail()
		}
	})
}
