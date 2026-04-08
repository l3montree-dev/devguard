package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"go.uber.org/fx"
)

func TestDependencyVulnControllerGetRecommendation(t *testing.T) {
	buildController := func(t *testing.T, depVulnRepo *mocks.DependencyVulnRepository) *controllers.DependencyVulnController {
		return controllers.NewDependencyVulnController(
			depVulnRepo,
			mocks.NewDependencyVulnService(t),
			mocks.NewProjectService(t),
			mocks.NewStatisticsService(t),
			mocks.NewVulnEventRepository(t),
			nil,
		)
	}

	t.Run("uses packageName/packageValue and returns extracted version", func(t *testing.T) {
		depVulnRepo := mocks.NewDependencyVulnRepository(t)
		controller := buildController(t, depVulnRepo)

		recommendedPurl := "pkg:npm/lodash@4.17.21"
		depVulnRepo.On("GetDirectDependencyFixedVersionByPackageName", mock.Anything, mock.Anything, "lodash").Return(&recommendedPurl, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/dependency_vuln/recommendation?packageName=lodash&packageValue=^4.0.0", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		err := controller.GetRecommendation(ctx)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response dtos.Recommendation
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		assert.Equal(t, "4.17.21", response.RecommendedVersion)
		depVulnRepo.AssertExpectations(t)
	})

	t.Run("uses depName/currentValue aliases and returns empty recommendation for non-PURL value", func(t *testing.T) {
		depVulnRepo := mocks.NewDependencyVulnRepository(t)
		controller := buildController(t, depVulnRepo)

		recommendedVersion := "2.3.4"
		depVulnRepo.On("GetDirectDependencyFixedVersionByPackageName", mock.Anything, mock.Anything, "leftpad").Return(&recommendedVersion, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/dependency_vuln/recommendation?depName=leftpad&currentValue=2.0.0", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		err := controller.GetRecommendation(ctx)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]string
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		assert.Equal(t, "", response["recommendedVersion"])
		depVulnRepo.AssertExpectations(t)
	})

	t.Run("returns empty recommendation when repository returns nil", func(t *testing.T) {
		depVulnRepo := mocks.NewDependencyVulnRepository(t)
		controller := buildController(t, depVulnRepo)

		depVulnRepo.On("GetDirectDependencyFixedVersionByPackageName", mock.Anything, mock.Anything, "chalk").Return((*string)(nil), nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/dependency_vuln/recommendation?packageName=chalk&packageValue=5.0.0", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		err := controller.GetRecommendation(ctx)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response dtos.Recommendation
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		assert.Equal(t, "", response.RecommendedVersion)
		depVulnRepo.AssertExpectations(t)
	})

	t.Run("returns bad request when package name params are missing", func(t *testing.T) {
		depVulnRepo := mocks.NewDependencyVulnRepository(t)
		controller := buildController(t, depVulnRepo)

		req := httptest.NewRequest(http.MethodGet, "/dependency_vuln/recommendation?packageValue=1.2.3", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		err := controller.GetRecommendation(ctx)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Equal(t, "missing packageName or depName", httpErr.Message)
		depVulnRepo.AssertNotCalled(t, "GetDirectDependencyFixedVersionByPackageName", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("returns bad request when current version params are missing", func(t *testing.T) {
		depVulnRepo := mocks.NewDependencyVulnRepository(t)
		controller := buildController(t, depVulnRepo)

		req := httptest.NewRequest(http.MethodGet, "/dependency_vuln/recommendation?packageName=react", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		err := controller.GetRecommendation(ctx)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Equal(t, "missing packageValue or currentValue", httpErr.Message)
		depVulnRepo.AssertNotCalled(t, "GetDirectDependencyFixedVersionByPackageName", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestDependencyVulnRecommendationRoute(t *testing.T) {
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
	}, func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		cve := models.CVE{CVE: "CVE-2024-99999"}
		assert.NoError(t, f.DB.Create(&cve).Error)

		recommendedVersion := "pkg:npm/lodash@4.17.21"
		depVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:                        cve.CVE,
			ComponentPurl:                "pkg:npm/left-pad@1.0.0",
			DirectDependencyFixedVersion: &recommendedVersion,
			VulnerabilityPath:            []string{"pkg:npm/lodash@4.0.0", "pkg:npm/left-pad@1.0.0"},
		}
		assert.NoError(t, f.DB.Create(&depVuln).Error)
		assert.Equal(t, org.ID, project.OrganizationID)

		server := api.NewServer()
		server.Echo.GET("/api/v1/renovate/recommendation/", f.App.DependencyVulnController.GetRecommendation)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/renovate/recommendation/?packageName=lodash&packageValue=^4.0.0", nil)
		rec := httptest.NewRecorder()
		server.Echo.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response dtos.Recommendation
		assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		assert.Equal(t, "4.17.21", response.RecommendedVersion)
	})
}

func TestDependencyVulnControllerCreateEvent(t *testing.T) {
	os.Setenv("FRONTEND_URL", "http://localhost:3000")

	factory, client := NewTestClientFactory(t)

	externalUserRepository := mocks.NewExternalUserRepository(t)
	externalUserRepository.On("FindByOrgID", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)

	projectService := mocks.NewProjectService(t)
	statisticsService := mocks.NewStatisticsService(t)
	vulnEventRepository := mocks.NewVulnEventRepository(t)

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Decorate(func() shared.ExternalUserRepository {
				return externalUserRepository
			}),
			fx.Decorate(func() shared.ProjectService {
				return projectService
			}),
			fx.Decorate(func() shared.StatisticsService {
				return statisticsService
			}),
			fx.Decorate(func() shared.VulnEventRepository {
				return vulnEventRepository
			}),
			fx.Decorate(func() shared.GitlabClientFactory {
				return factory
			}),
			fx.Decorate(func() map[string]*gitlabint.GitlabOauth2Config {
				return map[string]*gitlabint.GitlabOauth2Config{
					"gitlab": {},
				}
			}),
		},
	}, func(f *TestFixture) {

		thirdPartyIntegration := integrations.NewThirdPartyIntegrations(externalUserRepository, f.App.GitlabIntegration)

		// Create org, project, asset, asset version using FX helper
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		// Mark the asset as external provider
		asset.ExternalEntityProviderID = utils.Ptr("gitlab")
		asset.ExternalEntityID = utils.Ptr("123")
		assert.Nil(t, f.DB.Save(&asset).Error)

		t.Run("should reopen a ticket, if the dependency vuln is reopened", func(t *testing.T) {
			assetVersion := models.AssetVersion{
				AssetID:       asset.ID,
				Name:          "1.0.0",
				DefaultBranch: true,
			}
			assert.Nil(t, f.DB.Create(&assetVersion).Error)

			// Create a cve
			cve := models.CVE{
				CVE: "CVE-2023-12345",
			}
			assert.Nil(t, f.DB.Create(&cve).Error)

			// create the component "pkg:npm/test-package@1.0.0"
			component := models.Component{
				ID: "pkg:npm/test-package@1.0.0",
			}
			assert.Nil(t, f.DB.Create(&component).Error)
			// Create a dependency vuln with a ticket ID
			depVuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					State:                dtos.VulnStateAccepted,
					AssetVersionName:     assetVersion.Name,
					AssetID:              asset.ID,
					TicketID:             utils.Ptr("gitlab:0/123"),
					ManualTicketCreation: true,
				},
				ComponentPurl: "pkg:npm/test-package@1.0.0",
				CVEID:         cve.CVE,
			}
			assert.Nil(t, f.DB.Create(&depVuln).Error)

			msg := controllers.DependencyVulnStatus{
				StatusType:    "reopened",
				Justification: "Reopening the ticket for further investigation",
			}
			b, err := json.Marshal(msg)
			assert.Nil(t, err)

			req := httptest.NewRequest("POST", "/dependency_vuln/event", bytes.NewBuffer(b))
			rec := httptest.NewRecorder()
			ctx := NewContext(req, rec)

			session := mocks.NewAuthSession(t)
			session.On("GetUserID").Return("")
			shared.SetSession(ctx, session)
			// set the elements into the context
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetAssetVersion(ctx, assetVersion)
			ctx.SetParamNames("dependencyVulnID")
			ctx.SetParamValues(depVuln.ID.String())
			rbac := mocks.NewAccessControl(t)
			rbac.On("GetAllMembersOfOrganization").Return(nil, nil)
			shared.SetRBAC(ctx, rbac)

			adminClient := mocks.NewAdminClient(t)
			shared.SetAuthAdminClient(ctx, adminClient)
			shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

			client.On("CreateIssueComment", mock.Anything, 123, 123, mock.Anything).Return(nil, nil, nil)
			client.On("EditIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil, nil)
			// now reopen the dependency vuln
			err = f.App.DependencyVulnController.CreateEvent(ctx)
			assert.Nil(t, err)

			// check that the state event is reopened
			gitlabUpdateIssueOption := client.Calls[1].Arguments.Get(3).(*gitlab.UpdateIssueOptions)
			assert.Equal(t, "reopen", *gitlabUpdateIssueOption.StateEvent)
		})
	})
}
