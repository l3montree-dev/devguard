package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"go.uber.org/fx"
)

func TestDependencyVulnControllerCreateEvent(t *testing.T) {
	os.Setenv("FRONTEND_URL", "http://localhost:3000")

	factory, client := NewTestClientFactory(t)

	externalUserRepository := mocks.NewExternalUserRepository(t)
	externalUserRepository.On("FindByOrgID", mock.Anything, mock.Anything).Return(nil, nil)

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

			// Create a dependency vuln with a ticket ID
			depVuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					State:                dtos.VulnStateAccepted,
					AssetVersionName:     assetVersion.Name,
					AssetID:              asset.ID,
					TicketID:             utils.Ptr("gitlab:0/123"),
					ManualTicketCreation: true,
				},
				CVEID: utils.Ptr(cve.CVE),
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
			ctx.SetParamValues(depVuln.ID)
			rbac := mocks.NewAccessControl(t)
			rbac.On("GetAllMembersOfOrganization").Return(nil, nil)
			shared.SetRBAC(ctx, rbac)

			adminClient := mocks.NewAdminClient(t)
			shared.SetAuthAdminClient(ctx, adminClient)
			shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

			client.On("CreateIssueComment", ctx.Request().Context(), 123, 123, mock.Anything).Return(nil, nil, nil)
			client.On("EditIssue", ctx.Request().Context(), mock.Anything, mock.Anything, mock.Anything).Return(nil, nil, nil)
			// now reopen the dependency vuln
			err = f.App.DependencyVulnController.CreateEvent(ctx)
			assert.Nil(t, err)

			// check that the state event is reopened
			gitlabUpdateIssueOption := client.Calls[1].Arguments.Get(3).(*gitlab.UpdateIssueOptions)
			assert.Equal(t, "reopen", *gitlabUpdateIssueOption.StateEvent)
		})
	})
}
