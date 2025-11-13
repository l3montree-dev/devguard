package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestDependencyVulnController_CreateEvent(t *testing.T) {
	db, terminate := InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "http://localhost:3000")

	factory, client := NewTestClientFactory(t)
	gitlabIntegration := gitlabint.NewGitlabIntegration(
		db,
		map[string]*gitlabint.GitlabOauth2Config{
			"gitlab": {},
		},
		mocks.NewRBACProvider(t),
		factory,
	)

	externalUserRepository := mocks.NewExternalUserRepository(t)
	externalUserRepository.On("FindByOrgID", mock.Anything, mock.Anything).Return(nil, nil)

	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(externalUserRepository, gitlabIntegration)

	// Setup repositories and services
	depVulnRepo := repositories.NewDependencyVulnRepository(db)
	depVulnService := services.NewDependencyVulnService(
		depVulnRepo,
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		thirdPartyIntegration,
		repositories.NewAssetVersionRepository(db),
	)
	projectService := mocks.NewProjectService(t)

	statisticsService := mocks.NewStatisticsService(t)
	vulnEventRepository := mocks.NewVulnEventRepository(t)
	controller := controllers.NewDependencyVulnController(depVulnRepo, depVulnService, projectService, statisticsService, vulnEventRepository)

	// Create org, project, asset, asset version, and dependency vuln
	org, project, asset, _ := CreateOrgProjectAndAssetAssetVersion(db)

	// mark the asset as external provider
	asset.ExternalEntityProviderID = utils.Ptr("gitlab")
	asset.ExternalEntityID = utils.Ptr("123")
	assert.Nil(t, db.Save(&asset).Error)
	t.Run("should reopen a ticket, if the dependency vuln is reopened", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			AssetID:       asset.ID,
			Name:          "1.0.0",
			DefaultBranch: true,
		}
		assert.Nil(t, db.Create(&assetVersion).Error)
		// create a cve
		cve := models.CVE{
			CVE: "CVE-2023-12345",
		}
		assert.Nil(t, db.Create(&cve).Error)
		// create a dependency vuln with a ticket ID
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
		assert.Nil(t, db.Create(&depVuln).Error)

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
		err = controller.CreateEvent(ctx)
		assert.Nil(t, err)

		// check that the state event is reopened
		gitlabUpdateIssueOption := client.Calls[1].Arguments.Get(3).(*gitlab.UpdateIssueOptions)
		assert.Equal(t, "reopen", *gitlabUpdateIssueOption.StateEvent)
	})
}
