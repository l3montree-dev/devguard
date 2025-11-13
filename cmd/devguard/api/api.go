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
	"sort"
	"sync"
	"time"

	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/auth"
	middleware "github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/pubsub"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

func externalEntityProviderOrgSyncMiddleware(externalEntityProviderService shared.ExternalEntityProviderService) shared.MiddlewareFunc {
	limiter := &sync.Map{}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {

			key := shared.GetSession(ctx).GetUserID()
			now := time.Now()

			if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
				slog.Info("syncing external entity provider orgs", "userID", key)
				limiter.Store(key, now.Add(15*time.Minute))
				// Create a goroutine-safe context to avoid using the request context
				safeCtx := shared.GoroutineSafeContext(ctx)
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

func externalEntityProviderRefreshMiddleware(externalEntityProviderService shared.ExternalEntityProviderService) shared.MiddlewareFunc {
	limiter := &sync.Map{}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the current org
		return func(ctx shared.Context) error {
			org := shared.GetOrg(ctx)

			if org.IsExternalEntity() {
				key := org.GetID().String() + "/" + shared.GetSession(ctx).GetUserID()
				now := time.Now()

				// Check if we are allowed to refresh the external entity provider projects
				if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
					limiter.Store(key, now.Add(15*time.Minute))

					// Create a goroutine-safe context and capture the values we need
					safeCtx := shared.GoroutineSafeContext(ctx)
					userID := shared.GetSession(ctx).GetUserID()
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
		"userID": shared.GetSession(ctx).GetUserID(),
	})
}

func BuildRouter() *echo.Echo {
	projectScopedRBAC := middleware.ProjectAccessControlFactory(params.ProjectRepository)
	assetScopedRBAC := AssetAccessControlFactory(params.AssetRepository)

	server := echohttp.Server()

	shareRouter := apiV1Router.Group("/public/:assetID", shareMiddleware(orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	shareRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	shareRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	/**
	Expose vulnerability data publicly
	*/
	cveRouter := apiV1Router.Group("/vulndb")
	cveRouter.GET("/", vulndbController.ListPaged)
	cveRouter.GET("/:cveID/", vulndbController.Read)

	/**
	Everything below this line needs authentication
	*/
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(shared.NewAdminClient(ory), patService), externalEntityProviderOrgSyncMiddleware(externalEntityProviderService))
	sessionRouter.GET("/trigger-sync/", externalEntityProviderService.TriggerOrgSync, NeededScope([]string{"manage"}))
	sessionRouter.GET("/oauth2/gitlab/:integrationName/", integrationController.GitLabOauth2Login)
	sessionRouter.GET("/oauth2/gitlab/callback/:integrationName/", integrationController.GitLabOauth2Callback)
	sessionRouter.GET("/whoami/", whoami)
	sessionRouter.GET("/integrations/repositories/", integrationController.ListRepositories)
	sessionRouter.POST("/accept-invitation/", orgController.AcceptInvitation, NeededScope([]string{"manage"}))

	/**
	Following routes are asset routes which are registered on sessionRouter because of fast access.
	They do ALL need to have an assetScopedRBAC middleware applied to them.
	*/
	fastAccessRoutes := sessionRouter.Group("", NeededScope([]string{"scan"}), assetNameMiddleware(), MultiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService, gitlabOauth2Integrations),
		projectScopedRBAC(shared.ObjectProject, shared.ActionRead),
		assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))

	fastAccessRoutes.POST("/scan/", scanController.ScanDependencyVulnFromProject)
	fastAccessRoutes.POST("/vex/", scanController.UploadVEX)
	fastAccessRoutes.POST("/sarif-scan/", scanController.FirstPartyVulnScan)
	fastAccessRoutes.POST("/attestations/", attestationController.Create)

	/**
	Personal access token router
	This does not happen in a org or anything.
	We only need to make sure, that the user is logged in (sessionRouter)
	*/
	patRouter := sessionRouter.Group("/pats", NeededScope([]string{"manage"}))
	patRouter.GET("/", patController.List)
	patRouter.POST("/", patController.Create)
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey)
	patRouter.DELETE("/:tokenID/", patController.Delete)

	/**
	Organization router
	*/
	orgRouter := sessionRouter.Group("/organizations")
	orgRouter.GET("/", orgController.List)
	orgRouter.POST("/", orgController.Create, NeededScope([]string{"manage"}))

	/**
	Organization scoped router
	All routes below this line are scoped to a specific organization.
	*/
	organizationRouter := orgRouter.Group("/:organization", MultiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService, gitlabOauth2Integrations), OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionRead), externalEntityProviderRefreshMiddleware(externalEntityProviderService))

	organizationRouter.DELETE("/", orgController.Delete, NeededScope([]string{"manage"}), OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionDelete))

	organizationRouter.GET("/config-files/:config-file/", orgController.GetConfigFile)

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

	organizationUpdateAccessControlRequired := organizationRouter.Group("", NeededScope([]string{"manage"}), OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionUpdate))

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
	projectRouter := organizationRouter.Group("/projects/:projectSlug", projectScopedRBAC(shared.ObjectProject, shared.ActionRead))
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

	projectRouter.POST("/assets/", assetController.Create, NeededScope([]string{"manage"}), projectScopedRBAC(shared.ObjectAsset, shared.ActionCreate))

	projectUpdateAccessControlRequired := projectRouter.Group("", NeededScope([]string{"manage"}), projectScopedRBAC(shared.ObjectProject, shared.ActionUpdate))

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
	assetRouter := projectRouter.Group("/assets/:assetSlug", assetScopedRBAC(shared.ObjectAsset, shared.ActionRead))
	assetRouter.GET("/", assetController.Read)
	assetRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetRouter.GET("/compliance/:policy/", complianceController.Details)
	assetRouter.GET("/number-of-exploits/", statisticsController.GetCVESWithKnownExploits)
	assetRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	assetRouter.GET("/config-files/:config-file/", assetController.GetConfigFile)
	assetRouter.GET("/refs/", assetVersionController.GetAssetVersionsByAssetID)
	assetRouter.GET("/in-toto/root.layout.json/", intotoController.RootLayout)
	assetRouter.GET("/members/", assetController.Members)

	assetRouter.DELETE("/", assetController.Delete, NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionDelete))
	assetRouter.GET("/secrets/", assetController.GetSecrets, NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetRouter.POST("/signing-key/", assetController.AttachSigningKey, NeededScope([]string{"scan"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetRouter.POST("/in-toto/", intotoController.Create, NeededScope([]string{"scan"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))

	assetUpdateAccessControlRequired := assetRouter.Group("", NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetUpdateAccessControlRequired.POST("/sbom-file/", scanController.ScanSbomFile)
	assetUpdateAccessControlRequired.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup)
	assetUpdateAccessControlRequired.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup)
	assetUpdateAccessControlRequired.POST("/members/", assetController.InviteMembers)
	assetUpdateAccessControlRequired.PUT("/members/:userID/", assetController.ChangeRole)
	assetUpdateAccessControlRequired.PATCH("/", assetController.Update)
	assetUpdateAccessControlRequired.DELETE("/members/:userID/", assetController.RemoveMember)
	assetUpdateAccessControlRequired.POST("/refs/", assetVersionController.Create)

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
	assetVersionRouter.GET("/artifact-root-nodes/", assetVersionController.ReadRootNodes)

	assetVersionRouter.POST("/artifacts/", artifactController.Create, NeededScope([]string{"manage"}))

	assetVersionRouter.POST("/components/licenses/refresh/", assetVersionController.RefetchLicenses, NeededScope([]string{"manage"}))
	assetVersionRouter.DELETE("/", assetVersionController.Delete, NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetVersionRouter.POST("/make-default/", assetVersionController.MakeDefault, NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))

	artifactRouter := assetVersionRouter.Group("/artifacts/:artifactName", artifactMiddleware(artifactRepository))

	artifactRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	artifactRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	artifactRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	artifactRouter.GET("/openvex.json/", assetVersionController.OpenVEXJSON)
	artifactRouter.GET("/vex.xml/", assetVersionController.VEXXML)
	artifactRouter.GET("/sbom.pdf/", assetVersionController.BuildPDFFromSBOM)

	artifactRouter.DELETE("/", artifactController.DeleteArtifact, NeededScope([]string{"manage"}))
	artifactRouter.PUT("/", artifactController.UpdateArtifact, NeededScope([]string{"manage"}))
	artifactRouter.POST("/sync-external-sources/", artifactController.SyncExternalSources)

	dependencyVulnRouter := assetVersionRouter.Group("/dependency-vulns")
	dependencyVulnRouter.GET("/", dependencyVulnController.ListPaged)
	dependencyVulnRouter.GET("/sync/", dependencyVulnController.ListByAssetIDWithoutHandledExternalEventsPaged)
	dependencyVulnRouter.GET("/:dependencyVulnID/", dependencyVulnController.Read)
	dependencyVulnRouter.GET("/:dependencyVulnID/events/", vulnEventController.ReadAssetEventsByVulnID)
	dependencyVulnRouter.GET("/:dependencyVulnID/hints/", dependencyVulnController.Hints)

	dependencyVulnRouter.POST("/sync/", dependencyVulnController.SyncDependencyVulns, NeededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/:dependencyVulnID/", dependencyVulnController.CreateEvent, NeededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/:dependencyVulnID/mitigate/", dependencyVulnController.Mitigate, NeededScope([]string{"manage"}))

	firstPartyVulnRouter := assetVersionRouter.Group("/first-party-vulns")
	firstPartyVulnRouter.GET("/", firstPartyVulnController.ListPaged)
	firstPartyVulnRouter.GET("/:firstPartyVulnID/", firstPartyVulnController.Read)
	firstPartyVulnRouter.GET("/:firstPartyVulnID/events/", vulnEventController.ReadAssetEventsByVulnID)

	firstPartyVulnRouter.POST("/:firstPartyVulnID/", firstPartyVulnController.CreateEvent, NeededScope([]string{"manage"}))
	firstPartyVulnRouter.POST("/:firstPartyVulnID/mitigate/", firstPartyVulnController.Mitigate, NeededScope([]string{"manage"}))

	licenseRiskRouter := assetVersionRouter.Group("/license-risks")
	licenseRiskRouter.GET("/", licenseRiskController.ListPaged)
	licenseRiskRouter.GET("/:licenseRiskID/", licenseRiskController.Read)
	licenseRiskRouter.POST("/", licenseRiskController.Create, NeededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/", licenseRiskController.CreateEvent, NeededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/mitigate/", licenseRiskController.Mitigate, NeededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/final-license-decision/", licenseRiskController.MakeFinalLicenseDecision, NeededScope([]string{"manage"}))

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

func NewServer(lc fx.Lifecycle, db shared.DB, broker pubsub.Broker) *echo.Echo {
	srv := BuildRouter(db, broker)
	lc.Append(fx.StartHook(func() {
		slog.Error("failed to start server", "err", srv.Start(":8080").Error())
	}))
	return srv
}
