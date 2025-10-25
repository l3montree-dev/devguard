// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/attestation"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jiraint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/webhook"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/release"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/echohttp"
	"github.com/l3montree-dev/devguard/internal/pubsub"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

func externalEntityProviderOrgSyncMiddleware(externalEntityProviderService core.ExternalEntityProviderService) core.MiddlewareFunc {
	limiter := &sync.Map{}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {

			key := core.GetSession(ctx).GetUserID()
			now := time.Now()

			if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
				slog.Info("syncing external entity provider orgs", "userID", key)
				limiter.Store(key, now.Add(15*time.Minute))
				// Create a goroutine-safe context to avoid using the request context
				safeCtx := core.GoroutineSafeContext(ctx)
				go func() {
					if _, err := externalEntityProviderService.SyncOrgs(safeCtx); err != nil {
						slog.Error("could not sync external entity provider orgs", "err", err, "userID", key)
					}
				}()
			}
			return next(ctx)
		}
	}
}

func externalEntityProviderRefreshMiddleware(externalEntityProviderService core.ExternalEntityProviderService) core.MiddlewareFunc {
	limiter := &sync.Map{}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the current org
		return func(ctx core.Context) error {
			org := core.GetOrg(ctx)

			if org.IsExternalEntity() {
				key := org.GetID().String() + "/" + core.GetSession(ctx).GetUserID()
				now := time.Now()

				// Check if we are allowed to refresh the external entity provider projects
				if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
					limiter.Store(key, now.Add(15*time.Minute))

					// Create a goroutine-safe context and capture the values we need
					safeCtx := core.GoroutineSafeContext(ctx)
					userID := core.GetSession(ctx).GetUserID()
					orgID := org.GetID()

					go func() {
						err := externalEntityProviderService.RefreshExternalEntityProviderProjects(safeCtx, org, userID)
						if err != nil {
							slog.Error("could not refresh external entity provider projects", "err", err, "orgID", orgID, "userID", userID)
						} else {
							slog.Info("refreshed external entity provider projects", "orgID", orgID, "userID", userID)
						}
					}()
				}
			}

			return next(ctx)
		}
	}
}

func whoami(ctx echo.Context) error {
	return ctx.JSON(200, map[string]string{
		"userID": core.GetSession(ctx).GetUserID(),
	})
}

func health(ctx echo.Context) error {
	return ctx.String(200, "ok")
}

func BuildRouter(db core.DB, broker pubsub.Broker) *echo.Echo {
	ory := auth.GetOryAPIClient(os.Getenv("ORY_KRATOS_PUBLIC"))
	oryAdmin := auth.GetOryAPIClient(os.Getenv("ORY_KRATOS_ADMIN"))
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db, broker)
	if err != nil {
		panic(err)
	}

	webhookIntegration := webhook.NewWebhookIntegration(db)

	jiraIntegration := jiraint.NewJiraIntegration(db)

	githubIntegration := githubint.NewGithubIntegration(db)
	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)

	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integrations,
	)

	gitlabIntegration := gitlabint.NewGitlabIntegration(db, gitlabOauth2Integrations, casbinRBACProvider, gitlabClientFactory)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(repositories.NewExternalUserRepository(db), gitlabIntegration, githubIntegration, jiraIntegration, webhookIntegration)

	// init all repositories using the provided database
	patRepository := repositories.NewPATRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetRiskAggregationRepository := repositories.NewArtifactRiskHistoryRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	// release repository used by statistics for release-scoped stats
	releaseRepository := repositories.NewReleaseRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	projectScopedRBAC := projectAccessControlFactory(projectRepository)
	assetScopedRBAC := assetAccessControlFactory(assetRepository)
	orgRepository := repositories.NewOrgRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	intotoLinkRepository := repositories.NewInTotoLinkRepository(db)
	supplyChainRepository := repositories.NewSupplyChainRepository(db)
	attestationRepository := repositories.NewAttestationRepository(db)
	policyRepository := repositories.NewPolicyRepository(db)
	licenseRiskRepository := repositories.NewLicenseRiskRepository(db)
	webhookRepository := repositories.NewWebhookRepository(db)
	artifactRepository := repositories.NewArtifactRepository(db)

	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository, thirdPartyIntegration)
	projectService := project.NewService(projectRepository, assetRepository)

	assetService := asset.NewService(assetRepository, dependencyVulnRepository, dependencyVulnService)
	openSourceInsightsService := vulndb.NewOpenSourceInsightService()
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	licenseRiskService := vuln.NewLicenseRiskService(licenseRiskRepository, vulnEventRepository)
	componentService := component.NewComponentService(&openSourceInsightsService, componentProjectRepository, componentRepository, licenseRiskService, artifactRepository, utils.NewFireAndForgetSynchronizer())

	// release module
	// release repository will be created later when project router is available
	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository, projectRepository, orgRepository, vulnEventRepository, &componentService, thirdPartyIntegration, licenseRiskRepository)

	artifactService := artifact.NewService(artifactRepository, cveRepository, componentRepository, dependencyVulnRepository, assetRepository, assetVersionRepository, assetVersionService, dependencyVulnService)

	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, releaseRepository)
	invitationRepository := repositories.NewInvitationRepository(db)

	intotoService := intoto.NewInTotoService(casbinRBACProvider, intotoLinkRepository, projectRepository, patRepository, supplyChainRepository)

	orgService := org.NewService(orgRepository, casbinRBACProvider)

	externalEntityProviderService := integrations.NewExternalEntityProviderService(projectService, assetService, assetRepository, projectRepository, casbinRBACProvider, orgRepository)

	// init all http controllers using the repositories

	artifactController := artifact.NewController(artifactRepository, artifactService, dependencyVulnService, statisticsService)
	dependencyVulnController := vuln.NewHTTPController(dependencyVulnRepository, dependencyVulnService, projectService, statisticsService, vulnEventRepository)
	vulnEventController := events.NewVulnEventController(vulnEventRepository, assetVersionRepository)
	policyController := compliance.NewPolicyController(policyRepository, projectRepository)
	patController := pat.NewHTTPController(patRepository)
	orgController := org.NewHTTPController(orgRepository, orgService, casbinRBACProvider, projectService, invitationRepository)
	projectController := project.NewHTTPController(projectRepository, assetRepository, projectService, webhookRepository)
	assetController := asset.NewHTTPController(assetRepository, assetVersionRepository, assetService, dependencyVulnService, statisticsService, thirdPartyIntegration)

	scanController := scan.NewHTTPController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService, firstPartyVulnService, artifactService, dependencyVulnRepository)

	assetVersionController := assetversion.NewAssetVersionController(assetVersionRepository, assetVersionService, dependencyVulnRepository, componentRepository, dependencyVulnService, supplyChainRepository, licenseRiskRepository, &componentService, statisticsService, artifactService)
	attestationController := attestation.NewAttestationController(attestationRepository, assetVersionRepository, artifactRepository)
	intotoController := intoto.NewHTTPController(intotoLinkRepository, supplyChainRepository, assetVersionRepository, patRepository, intotoService)
	componentController := component.NewHTTPController(componentRepository, assetVersionRepository, licenseRiskRepository)
	complianceController := compliance.NewHTTPController(assetVersionRepository, attestationRepository, policyRepository)
	statisticsController := statistics.NewHTTPController(statisticsService, statisticsRepository, assetRepository, assetVersionRepository, projectService)
	firstPartyVulnController := vuln.NewFirstPartyVulnController(firstPartyVulnRepository, firstPartyVulnService, projectService)
	licenseRiskController := vuln.NewLicenseRiskController(licenseRiskRepository, licenseRiskService)
	// release routes inside project scope
	releaseRepository = repositories.NewReleaseRepository(db)
	releaseService := release.NewService(releaseRepository)

	releaseController := release.NewReleaseController(releaseService, assetVersionService, assetVersionRepository, componentRepository, licenseRiskRepository, dependencyVulnRepository, assetRepository)

	patService := pat.NewPatService(patRepository)

	vulndbController := vulndb.NewHTTPController(cveRepository)

	server := echohttp.Server()

	integrationController := integrations.NewIntegrationController(gitlabOauth2Integrations)

	apiV1Router := server.Group("/api/v1")
	// this makes the third party integrations available to all controllers
	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)
			return next(ctx)
		}
	})

	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// set the ory admin client to the context
			core.SetAuthAdminClient(ctx, core.NewAdminClient(oryAdmin))
			return next(ctx)
		}
	})

	apiV1Router.GET("/metrics/", echo.WrapHandler(promhttp.Handler()))
	apiV1Router.GET("/health/", health)
	apiV1Router.GET("/badges/:badge/:badgeSecret/", assetController.GetBadges)
	apiV1Router.GET("/lookup/", assetController.HandleLookup)
	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)
	apiV1Router.POST("/webhook/", thirdPartyIntegration.HandleWebhook)
	/**
	Expose vulnerability data publicly
	*/
	cveRouter := apiV1Router.Group("/vulndb")
	cveRouter.GET("/", vulndbController.ListPaged)
	cveRouter.GET("/:cveID/", vulndbController.Read)

	/**
	Everything below this line needs authentication
	*/
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(core.NewAdminClient(ory), patService), externalEntityProviderOrgSyncMiddleware(externalEntityProviderService))
	sessionRouter.GET("/trigger-sync/", externalEntityProviderService.TriggerOrgSync, neededScope([]string{"manage"}))
	sessionRouter.GET("/oauth2/gitlab/:integrationName/", integrationController.GitLabOauth2Login)
	sessionRouter.GET("/oauth2/gitlab/callback/:integrationName/", integrationController.GitLabOauth2Callback)
	sessionRouter.GET("/whoami/", whoami)
	sessionRouter.GET("/integrations/repositories/", integrationController.ListRepositories)
	sessionRouter.POST("/accept-invitation/", orgController.AcceptInvitation, neededScope([]string{"manage"}))

	/**
	Following routes are asset routes which are registered on sessionRouter because of fast access.
	They do ALL need to have an assetScopedRBAC middleware applied to them.
	*/
	fastAccessRoutes := sessionRouter.Group("", neededScope([]string{"scan"}), assetNameMiddleware(), multiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService, gitlabOauth2Integrations),
		projectScopedRBAC(core.ObjectProject, core.ActionRead),
		assetScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	fastAccessRoutes.POST("/scan/", scanController.ScanDependencyVulnFromProject)
	fastAccessRoutes.POST("/vex/", scanController.UploadVEX)
	fastAccessRoutes.POST("/sarif-scan/", scanController.FirstPartyVulnScan)
	fastAccessRoutes.POST("/attestations/", attestationController.Create)

	/**
	Personal access token router
	This does not happen in a org or anything.
	We only need to make sure, that the user is logged in (sessionRouter)
	*/
	patRouter := sessionRouter.Group("/pats", neededScope([]string{"manage"}))
	patRouter.GET("/", patController.List)
	patRouter.POST("/", patController.Create)
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey)
	patRouter.DELETE("/:tokenID/", patController.Delete)

	/**
	Organization router
	*/
	orgRouter := sessionRouter.Group("/organizations")
	orgRouter.GET("/", orgController.List)
	orgRouter.POST("/", orgController.Create, neededScope([]string{"manage"}))

	/**
	Organization scoped router
	All routes below this line are scoped to a specific organization.
	*/
	organizationRouter := orgRouter.Group("/:organization", multiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService, gitlabOauth2Integrations), organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionRead), externalEntityProviderRefreshMiddleware(externalEntityProviderService))

	organizationRouter.DELETE("/", orgController.Delete, neededScope([]string{"manage"}), organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionDelete))

	organizationRouter.GET("/trigger-sync/", externalEntityProviderService.TriggerSync)
	organizationRouter.GET("/", orgController.Read)
	organizationRouter.GET("/metrics/", orgController.Metrics)
	organizationRouter.GET("/content-tree/", orgController.ContentTree)
	organizationRouter.GET("/dependency-vulns/", dependencyVulnController.ListByOrgPaged)
	organizationRouter.GET("/first-party-vulns/", firstPartyVulnController.ListByOrgPaged)
	organizationRouter.GET("/policies/", policyController.GetOrganizationPolicies)
	organizationRouter.GET("/policies/:policyID/", policyController.GetPolicy)
	organizationRouter.GET("/members/", orgController.Members)
	organizationRouter.GET("/integrations/finish-installation/", integrationController.FinishInstallation)
	organizationRouter.GET("/config-files/:config-file/", orgController.GetConfigFile)
	organizationRouter.GET("/projects/", projectController.List)
	organizationRouter.GET("/integrations/repositories/", integrationController.ListRepositories)

	organizationUpdateAccessControlRequired := organizationRouter.Group("", neededScope([]string{"manage"}), organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))

	organizationUpdateAccessControlRequired.POST("/members/", orgController.InviteMember)
	organizationUpdateAccessControlRequired.POST("/integrations/jira/test-and-save/", integrationController.TestAndSaveJiraIntegration)
	organizationUpdateAccessControlRequired.POST("/integrations/webhook/test-and-save/", webhookIntegration.Save)
	organizationUpdateAccessControlRequired.POST("/integrations/webhook/test/", webhookIntegration.Test)
	organizationUpdateAccessControlRequired.POST("/policies/", policyController.CreatePolicy)
	organizationUpdateAccessControlRequired.POST("/integrations/gitlab/test-and-save/", integrationController.TestAndSaveGitlabIntegration)
	organizationUpdateAccessControlRequired.POST("/projects/", projectController.Create)

	organizationUpdateAccessControlRequired.DELETE("/policies/:policyID/", policyController.DeletePolicy)
	organizationUpdateAccessControlRequired.DELETE("/integrations/gitlab/:gitlab_integration_id/", integrationController.DeleteGitLabAccessToken)
	organizationUpdateAccessControlRequired.DELETE("/members/:userID/", orgController.RemoveMember)
	organizationUpdateAccessControlRequired.DELETE("/integrations/jira/:jira_integration_id/", integrationController.DeleteJiraAccessToken)
	organizationUpdateAccessControlRequired.DELETE("/integrations/webhook/:id/", webhookIntegration.Delete)

	organizationUpdateAccessControlRequired.PATCH("/", orgController.Update)
	organizationUpdateAccessControlRequired.PUT("/policies/:policyID/", policyController.UpdatePolicy)
	organizationUpdateAccessControlRequired.PUT("/members/:userID/", orgController.ChangeRole)
	organizationUpdateAccessControlRequired.PUT("/integrations/webhook/:id/", webhookIntegration.Update)

	/**
	Project scoped router
	All routes below this line are scoped to a specific project.
	*/
	projectRouter := organizationRouter.Group("/projects/:projectSlug", projectScopedRBAC(core.ObjectProject, core.ActionRead))
	projectRouter.GET("/", projectController.Read)
	projectRouter.GET("/policies/", policyController.GetProjectPolicies)
	projectRouter.GET("/dependency-vulns/", dependencyVulnController.ListByProjectPaged)
	projectRouter.GET("/assets/", assetController.List)
	projectRouter.GET("/members/", projectController.Members)
	projectRouter.GET("/config-files/:config-file/", projectController.GetConfigFile)
	projectRouter.GET("/releases/:releaseID/sbom.json/", releaseController.SBOMJSON)
	projectRouter.GET("/releases/:releaseID/sbom.xml/", releaseController.SBOMXML)
	projectRouter.GET("/releases/:releaseID/vex.json/", releaseController.VEXJSON)
	projectRouter.GET("/releases/:releaseID/vex.xml/", releaseController.VEXXML)
	projectRouter.GET("/releases/:releaseID/stats/risk-history/", statisticsController.GetReleaseRiskHistory)
	projectRouter.GET("/releases/:releaseID/stats/average-fixing-time/", statisticsController.GetAverageReleaseFixingTime)
	projectRouter.GET("/releases/:releaseID/candidates/", releaseController.ListCandidates)
	projectRouter.GET("/releases/candidates/", releaseController.ListCandidates)
	projectRouter.GET("/releases/:releaseID/", releaseController.Read)
	projectRouter.GET("/releases/", releaseController.List)

	projectRouter.POST("/assets/", assetController.Create, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionCreate))

	projectUpdateAccessControlRequired := projectRouter.Group("", neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionUpdate))

	projectUpdateAccessControlRequired.POST("/integrations/webhook/test-and-save/", webhookIntegration.Save)
	projectUpdateAccessControlRequired.POST("/integrations/webhook/test/", webhookIntegration.Test)
	projectUpdateAccessControlRequired.POST("/members/", projectController.InviteMembers)
	projectUpdateAccessControlRequired.POST("/releases/", releaseController.Create)
	projectUpdateAccessControlRequired.POST("/releases/:releaseID/items/", releaseController.AddItem)

	projectUpdateAccessControlRequired.DELETE("/integrations/webhook/:id/", webhookIntegration.Delete)
	projectUpdateAccessControlRequired.DELETE("/policies/:policyID/", policyController.DisablePolicyForProject)
	projectUpdateAccessControlRequired.DELETE("/", projectController.Delete)
	projectUpdateAccessControlRequired.DELETE("/members/:userID/", projectController.RemoveMember)
	projectUpdateAccessControlRequired.DELETE("/releases/:releaseID/", releaseController.Delete)
	projectUpdateAccessControlRequired.DELETE("/releases/:releaseID/items/:itemID/", releaseController.RemoveItem)

	projectUpdateAccessControlRequired.PUT("/integrations/webhook/:id/", webhookIntegration.Update)
	projectUpdateAccessControlRequired.PUT("/policies/:policyID/", policyController.EnablePolicyForProject)
	projectUpdateAccessControlRequired.PATCH("/", projectController.Update)
	projectUpdateAccessControlRequired.PUT("/members/:userID/", projectController.ChangeRole)
	projectUpdateAccessControlRequired.PATCH("/releases/:releaseID/", releaseController.Update)

	/**
	Asset scoped router
	All routes below this line are scoped to a specific asset.
	*/
	assetRouter := projectRouter.Group("/assets/:assetSlug", assetScopedRBAC(core.ObjectAsset, core.ActionRead))
	assetRouter.GET("/", assetController.Read)
	assetRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetRouter.GET("/compliance/:policy/", complianceController.Details)
	assetRouter.GET("/number-of-exploits/", statisticsController.GetCVESWithKnownExploits)
	assetRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	assetRouter.GET("/config-files/:config-file/", assetController.GetConfigFile)
	assetRouter.GET("/refs/", assetVersionController.GetAssetVersionsByAssetID)
	assetRouter.GET("/in-toto/root.layout.json/", intotoController.RootLayout)
	assetRouter.GET("/members/", assetController.Members)

	assetRouter.DELETE("/", assetController.Delete, neededScope([]string{"manage"}), assetScopedRBAC(core.ObjectAsset, core.ActionDelete))
	assetRouter.GET("/secrets/", assetController.GetSecrets, neededScope([]string{"manage"}), assetScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	assetRouter.POST("/signing-key/", assetController.AttachSigningKey, neededScope([]string{"scan"}), assetScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	assetRouter.POST("/in-toto/", intotoController.Create, neededScope([]string{"scan"}), assetScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	assetUpdateAccessControlRequired := assetRouter.Group("", neededScope([]string{"manage"}), assetScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	assetUpdateAccessControlRequired.POST("/sbom-file/", scanController.ScanSbomFile)
	assetUpdateAccessControlRequired.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup)
	assetUpdateAccessControlRequired.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup)
	assetUpdateAccessControlRequired.POST("/members/", assetController.InviteMembers)
	assetUpdateAccessControlRequired.PUT("/members/:userID/", assetController.ChangeRole)
	assetUpdateAccessControlRequired.PATCH("/", assetController.Update)
	assetUpdateAccessControlRequired.DELETE("/members/:userID/", assetController.RemoveMember)

	assetVersionRouter := assetRouter.Group("/refs/:assetVersionSlug", assetVersionMiddleware(assetVersionRepository))

	assetVersionRouter.GET("/sarif.json/", firstPartyVulnController.Sarif)
	assetVersionRouter.GET("/", assetVersionController.Read)
	assetVersionRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetVersionRouter.GET("/compliance/:policy/", complianceController.Details)
	assetVersionRouter.GET("/metrics/", assetVersionController.Metrics)
	assetVersionRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	assetVersionRouter.GET("/vulnerability-report.pdf/", assetVersionController.BuildVulnerabilityReportPDF)
	assetVersionRouter.GET("/affected-components/", assetVersionController.AffectedComponents)
	assetVersionRouter.GET("/dependency-graph/", assetVersionController.DependencyGraph)
	assetVersionRouter.GET("/path-to-component/", assetVersionController.GetDependencyPathFromPURL)
	assetVersionRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageFixingTime)
	assetVersionRouter.GET("/stats/risk-history/", statisticsController.GetArtifactRiskHistory)
	assetVersionRouter.GET("/stats/component-risk/", statisticsController.GetComponentRisk)
	assetVersionRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	assetVersionRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	assetVersionRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	assetVersionRouter.GET("/openvex.json/", assetVersionController.OpenVEXJSON)
	assetVersionRouter.GET("/vex.xml/", assetVersionController.VEXXML)
	assetVersionRouter.GET("/sbom.pdf/", assetVersionController.BuildPDFFromSBOM)
	assetVersionRouter.GET("/attestations/", attestationController.List)
	assetVersionRouter.GET("/in-toto/:supplyChainID/", intotoController.Read)
	assetVersionRouter.GET("/components/", componentController.ListPaged)
	assetVersionRouter.GET("/events/", vulnEventController.ReadEventsByAssetIDAndAssetVersionName)
	assetVersionRouter.GET("/artifacts/", assetVersionController.ListArtifacts)

	assetVersionRouter.POST("/artifacts/", artifactController.Create, neededScope([]string{"manage"}))

	assetVersionRouter.POST("/components/licenses/refresh/", assetVersionController.RefetchLicenses, neededScope([]string{"manage"}))
	assetVersionRouter.DELETE("/", assetVersionController.Delete, neededScope([]string{"manage"}), assetScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	artifactRouter := assetVersionRouter.Group("/artifacts/:artifactName", artifactMiddleware(artifactRepository))

	artifactRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	artifactRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	artifactRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	artifactRouter.GET("/openvex.json/", assetVersionController.OpenVEXJSON)
	artifactRouter.GET("/vex.xml/", assetVersionController.VEXXML)
	artifactRouter.GET("/sbom.pdf/", assetVersionController.BuildPDFFromSBOM)

	artifactRouter.DELETE("/", artifactController.DeleteArtifact, neededScope([]string{"manage"}))
	artifactRouter.PUT("/", artifactController.UpdateArtifact, neededScope([]string{"manage"}))

	dependencyVulnRouter := assetVersionRouter.Group("/dependency-vulns")
	dependencyVulnRouter.GET("/", dependencyVulnController.ListPaged)
	dependencyVulnRouter.GET("/sync/", dependencyVulnController.ListByAssetIDWithoutHandledExternalEventsPaged)
	dependencyVulnRouter.GET("/:dependencyVulnID/", dependencyVulnController.Read)
	dependencyVulnRouter.GET("/:dependencyVulnID/events/", vulnEventController.ReadAssetEventsByVulnID)
	dependencyVulnRouter.GET("/:dependencyVulnID/hints/", dependencyVulnController.Hints)

	dependencyVulnRouter.POST("/sync/", dependencyVulnController.SyncDependencyVulns, neededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/:dependencyVulnID/", dependencyVulnController.CreateEvent, neededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/:dependencyVulnID/mitigate/", dependencyVulnController.Mitigate, neededScope([]string{"manage"}))

	firstPartyVulnRouter := assetVersionRouter.Group("/first-party-vulns")
	firstPartyVulnRouter.GET("/", firstPartyVulnController.ListPaged)
	firstPartyVulnRouter.GET("/:firstPartyVulnID/", firstPartyVulnController.Read)
	firstPartyVulnRouter.GET("/:firstPartyVulnID/events/", vulnEventController.ReadAssetEventsByVulnID)

	firstPartyVulnRouter.POST("/:firstPartyVulnID/", firstPartyVulnController.CreateEvent, neededScope([]string{"manage"}))
	firstPartyVulnRouter.POST("/:firstPartyVulnID/mitigate/", firstPartyVulnController.Mitigate, neededScope([]string{"manage"}))

	licenseRiskRouter := assetVersionRouter.Group("/license-risks")
	licenseRiskRouter.GET("/", licenseRiskController.ListPaged)
	licenseRiskRouter.GET("/:licenseRiskID/", licenseRiskController.Read)
	licenseRiskRouter.POST("/", licenseRiskController.Create, neededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/", licenseRiskController.CreateEvent, neededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/mitigate/", licenseRiskController.Mitigate, neededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/final-license-decision/", licenseRiskController.MakeFinalLicenseDecision, neededScope([]string{"manage"}))

	routes := server.Routes()
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Path < routes[j].Path
	})
	// print all registered routes
	for _, route := range routes {
		if route.Method != "echo_route_not_found" {
			slog.Info(route.Path, "method", route.Method)
		}
	}
	return server
}

func Start(db core.DB, broker pubsub.Broker) {
	slog.Error("failed to start server", "err", BuildRouter(db, broker).Start(":8080").Error())
}
