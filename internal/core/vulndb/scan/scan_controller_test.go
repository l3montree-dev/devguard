package scan

import (
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

func TestCreateIssuesForVulns(t *testing.T) {
	t.Run("shouldn't crash if no threshold is provided", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest("", "http://localhost", nil)
		rec := httptest.NewRecorder()
		asset := models.Asset{}
		mockIntegrationAggregate := mocks.NewCoreIntegrationAggregate(t)

		ctx := e.NewContext(req, rec)
		core.SetAsset(ctx, asset)
		core.SetThirdPartyIntegration(ctx, mockIntegrationAggregate)

		err := createIssuesForVulns([]models.DependencyVuln{}, ctx)

		if err != nil {
			t.Fail()
		}
	})
	t.Run("shouldn't crash if an empty slice is passed", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest("", "http://localhost", nil)
		rec := httptest.NewRecorder()
		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(2.),
		}
		mockIntegrationAggregate := mocks.NewCoreIntegrationAggregate(t)

		ctx := e.NewContext(req, rec)
		core.SetAsset(ctx, asset)
		core.SetThirdPartyIntegration(ctx, mockIntegrationAggregate)

		err := createIssuesForVulns([]models.DependencyVuln{}, ctx)

		if err != nil {
			t.Fail()
		}
	})

	t.Run("should create a ticket if only a cvss score is provided and the CVE value is above the threshold", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest("", "http://localhost", nil)
		rec := httptest.NewRecorder()
		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(2.),
		}
		mockIntegrationAggregate := mocks.NewCoreIntegrationAggregate(t)
		mockIntegrationAggregate.On("HandleEvent", mock.Anything).Return(nil)

		ctx := e.NewContext(req, rec)
		core.SetAsset(ctx, asset)
		core.SetThirdPartyIntegration(ctx, mockIntegrationAggregate)

		err := createIssuesForVulns([]models.DependencyVuln{
			{
				CVE: &models.CVE{
					CVSS: 4,
				},
			},
		}, ctx)

		if err != nil {
			t.Fail()
		}
	})
	t.Run("should create a ticket if only a risk score is provided and the risk value is equal to the threshold", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest("", "http://localhost", nil)
		rec := httptest.NewRecorder()
		asset := models.Asset{
			RiskAutomaticTicketThreshold: utils.Ptr(2.),
		}
		mockIntegrationAggregate := mocks.NewCoreIntegrationAggregate(t)
		mockIntegrationAggregate.On("HandleEvent", mock.Anything).Return(nil)

		ctx := e.NewContext(req, rec)
		core.SetAsset(ctx, asset)
		core.SetThirdPartyIntegration(ctx, mockIntegrationAggregate)

		err := createIssuesForVulns([]models.DependencyVuln{
			{
				RawRiskAssessment: utils.Ptr(2.),
			},
		}, ctx)

		if err != nil {
			t.Fail()
		}
	})
	t.Run("should create a ticket if the cvss score or the risk score is above the respective threshold", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest("", "http://localhost", nil)
		rec := httptest.NewRecorder()
		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(2.),
			RiskAutomaticTicketThreshold: utils.Ptr(2.),
		}
		mockIntegrationAggregate := mocks.NewCoreIntegrationAggregate(t)
		mockIntegrationAggregate.On("HandleEvent", mock.Anything).Return(nil)

		ctx := e.NewContext(req, rec)
		core.SetAsset(ctx, asset)
		core.SetThirdPartyIntegration(ctx, mockIntegrationAggregate)

		err := createIssuesForVulns([]models.DependencyVuln{
			{
				RawRiskAssessment: utils.Ptr(2.),
				CVE: &models.CVE{
					CVSS: 4,
				},
			},
		}, ctx)

		if err != nil {
			t.Fail()
		}
	})

}
