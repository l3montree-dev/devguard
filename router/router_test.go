// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package router

// TestNonGetRoutesBlockPublicRequests enforces the invariant:
//
//	Every non-GET route that lives under /organizations must block a
//	fully-authenticated user that has NO membership in a public resource.
//
// Threat model: when an org/project/asset is marked public, the group-level
// RBAC middleware sets IsPublicRequest=true and continues processing. A
// non-GET route that is missing DisallowPublicRequests or a write-action RBAC
// check will pass the middleware chain and reach its handler. Because the
// handler is a zero-value stub it panics → 500.  Any properly protected route
// returns 4xx before the handler and the test passes.
//
// TestReadOnlyMemberCannotWriteToProtectedRoutes enforces the invariant:
//
//	Every non-GET route that requires explicit write permission must block a
//	read-only member (has ActionRead access but not ActionUpdate/ActionDelete).
//
// Routes listed in memberOnlyPaths intentionally use DisallowPublicRequests
// instead of write-level RBAC: any authenticated member (not just writers)
// is allowed. Those are skipped from the second test.
//
// HOW TO ADD NEW ROUTERS
// If you add a new router to RouterModule (providers.go) and it registers
// non-GET routes, register it in buildSecurityTestServer below and ensure it
// is called so the routes appear in e.Routes().
//
// HOW TO ADD AN INTENTIONALLY PUBLIC NON-GET ROUTE
// Add its exact path template to intentionallyPublicPaths below and explain
// why it is safe without authentication.
//
// HOW TO ADD A MEMBER-ONLY WRITE ROUTE (DisallowPublicRequests, no write RBAC)
// Add "METHOD /path/template/" to memberOnlyPaths and explain why any member
// (not just a writer) should be allowed.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/controllers/dependencyfirewall"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// intentionallyPublicPaths lists non-GET route path templates that are
// explicitly designed to be callable without membership in the resource.
// Each entry must include a comment explaining why it is safe.
var intentionallyPublicPaths = map[string]bool{
	// none yet
}

// memberOnlyPaths lists non-GET routes that are intentionally accessible to
// any authenticated member (not restricted to writers). They use
// DisallowPublicRequests instead of write-level RBAC because the business rule
// is: "if you can read the resource you can also perform this action."
// Key format: "METHOD /full/echo/path/template/"
var memberOnlyPaths = map[string]bool{
	// Vuln triage actions — any member who can read the asset version may triage findings.
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/sync/":                            true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/batch/":                           true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/":               true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/mitigate/":      true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/:firstPartyVulnID/":              true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/:firstPartyVulnID/mitigate/":     true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/license-risks/":                                    true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/":                     true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/mitigate/":            true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/final-license-decision/": true,
	// VEX rules — any member may create/edit/delete VEX rules (membership = passed read RBAC).
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/vex-rules/":                 true,
	"PUT /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/vex-rules/:ruleId/":          true,
	"POST /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/vex-rules/:ruleId/reapply/": true,
	"DELETE /api/v1/organizations/:organization/projects/:project/assets/:assetSlug/refs/:assetVersionSlug/vex-rules/:ruleId/":       true,
}

var echoParamRe = regexp.MustCompile(`:[^/]+`)

// fillParams replaces every Echo path parameter with a stable dummy value so
// the router can match the route without a real database record.
func fillParams(path string) string {
	return echoParamRe.ReplaceAllString(path, "test-id")
}

func buildSecurityTestServer(t *testing.T, ac *mocks.AccessControl) *echo.Echo {
	t.Helper()

	// middlewares.Server() sets the package-level middlewares.E used by
	// GoroutineSafeContext inside ExternalEntityProviderOrgSyncMiddleware.
	e := middlewares.Server()
	// Surface panics as 500 so the assertion can catch unprotected handlers.
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		code := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
		}
		_ = c.NoContent(code)
	}

	orgID := uuid.New()
	projectID := uuid.New()
	assetID := uuid.New()

	//  PAT service / verifier
	// Any request is treated as coming from "test-user" with manage+scan scopes
	// so NeededScope middleware always passes.  The real protection must then
	// come from DisallowPublicRequests or a write-action RBAC check.
	patService := &mocks.PersonalAccessTokenService{}
	patService.On("VerifyRequestSignature", mock.Anything, mock.Anything).
		Maybe().Return("test-user", "manage scan", nil)

	rbacProvider := &mocks.RBACProvider{}
	rbacProvider.On("GetDomainRBAC", mock.Anything).Maybe().Return(ac)

	//  Domain objects (all public so group RBAC sets IsPublicRequest)
	org := &models.Org{Model: models.Model{ID: orgID}, Slug: "test-org", IsPublic: true}
	orgService := &mocks.OrgService{}
	orgService.On("ReadBySlug", mock.Anything, mock.Anything).Maybe().Return(org, nil)

	proj := models.Project{Model: models.Model{ID: projectID}, Slug: "test-project", IsPublic: true}
	projectRepo := &mocks.ProjectRepository{}
	projectRepo.On("ReadBySlug", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(proj, nil)

	asset := models.Asset{Model: models.Model{ID: assetID}, Slug: "test-asset", IsPublic: true}
	assetRepo := &mocks.AssetRepository{}
	assetRepo.On("ReadBySlug", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(asset, nil)

	// AssetVersion: always not found → AssetVersionMiddleware returns a 404
	// which is still < 500, so sub-routes that rely on it are implicitly safe.
	assetVersionRepo := &mocks.AssetVersionRepository{}
	assetVersionRepo.On("ReadBySlug", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Maybe().Return(models.AssetVersion{}, fmt.Errorf("not found"))

	// VulnEvent: no access → EventMiddleware returns 403
	vulnEventRepo := &mocks.VulnEventRepository{}
	vulnEventRepo.On("HasAccessToEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Maybe().Return(false, nil)

	// Artifact: not found → ArtifactMiddleware returns 404
	artifactRepo := &mocks.ArtifactRepository{}
	artifactRepo.On("ReadArtifact", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Maybe().Return(models.Artifact{}, fmt.Errorf("not found"))

	// ExternalEntityProviderService: methods used as handlers (GET only) or
	// fire-and-forget goroutines; just needs to not crash on method-value take.
	extEntityService := &mocks.ExternalEntityProviderService{}
	extEntityService.On("SyncOrgs", mock.Anything).Maybe().Return([]*models.Org{}, nil)
	extEntityService.On("TriggerOrgSync", mock.Anything).Maybe().Return(nil)
	extEntityService.On("TriggerSync", mock.Anything).Maybe().Return(nil)

	// ConfigService: return error so InstanceSettings middleware passes through
	configService := &mocks.ConfigService{}
	configService.On("GetInstanceSettings", mock.Anything).
		Maybe().Return(models.Config{}, fmt.Errorf("not found"))

	// PublicClient: return error → SessionMiddleware falls through to PAT verifier
	publicClient := &mocks.PublicClient{}
	publicClient.On("GetIdentityFromCookie", mock.Anything, mock.Anything).
		Maybe().Return(nil, fmt.Errorf("no cookie"))

	//  Build the full router hierarchy using the REAL constructors
	// This is the point: if someone adds a route without protection and also
	// registers it here (or in RouterModule), the test will catch it.
	//
	// Use new(T) instead of nil for controllers: some methods use value
	// receivers, and taking a method value from a nil pointer panics.
	apiV1 := APIV1Router{Group: e.Group("/api/v1")}

	sessionRouter := NewSessionRouter(
		apiV1,
		publicClient,
		patService,
		extEntityService,
		new(controllers.IntegrationController),
		new(controllers.OrgController),
		new(controllers.ScanController),
		new(controllers.AttestationController),
		new(controllers.PatController),
		assetRepo,
		projectRepo,
		rbacProvider,
		orgService,
		map[string]*gitlabint.GitlabOauth2Config{},
		assetVersionRepo,
	)

	orgRouter := NewOrgRouter(
		sessionRouter,
		configService,
		new(controllers.OrgController),
		new(controllers.ProjectController),
		new(dependencyfirewall.DependencyProxyController),
		new(controllers.DependencyVulnController),
		new(controllers.FirstPartyVulnController),
		new(controllers.PolicyController),
		new(controllers.IntegrationController),
		new(controllers.WebhookController),
		extEntityService,
		orgService,
		map[string]*gitlabint.GitlabOauth2Config{},
		rbacProvider,
		new(controllers.StatisticsController),
	)

	projectRouter := NewProjectRouter(
		orgRouter,
		new(controllers.ProjectController),
		new(controllers.AssetController),
		new(dependencyfirewall.DependencyProxyController),
		new(controllers.DependencyVulnController),
		new(controllers.PolicyController),
		new(controllers.ReleaseController),
		new(controllers.StatisticsController),
		new(controllers.WebhookController),
		projectRepo,
		new(controllers.ComponentController),
	)

	assetRouter := NewAssetRouter(
		projectRouter,
		new(controllers.AssetController),
		new(dependencyfirewall.DependencyProxyController),
		new(controllers.AssetVersionController),
		new(controllers.ComplianceController),
		new(controllers.StatisticsController),
		new(controllers.ComponentController),
		new(controllers.InToToController),
		new(controllers.IntegrationController),
		new(controllers.ScanController),
		assetRepo,
	)

	assetVersionRouter := NewAssetVersionRouter(
		assetRouter,
		new(controllers.AssetVersionController),
		new(controllers.FirstPartyVulnController),
		new(controllers.ComplianceController),
		new(controllers.ComponentController),
		new(controllers.StatisticsController),
		new(controllers.AttestationController),
		new(controllers.InToToController),
		new(controllers.VulnEventController),
		new(controllers.ArtifactController),
		new(controllers.ExternalReferenceController),
		assetVersionRepo,
		assetRepo,
		vulnEventRepo,
	)

	// Sub-routers under /refs/:assetVersionSlug — all non-GET routes in these
	// must be protected.  Add new routers from RouterModule (providers.go) here.
	NewDependencyVulnRouter(assetVersionRouter, new(controllers.DependencyVulnController), new(controllers.VulnEventController))
	NewFirstPartyVulnRouter(assetVersionRouter, new(controllers.FirstPartyVulnController), new(controllers.VulnEventController))
	NewLicenseRiskRouter(assetVersionRouter, new(controllers.LicenseRiskController))
	NewVEXRuleRouter(assetVersionRouter, new(controllers.VEXRuleController))
	NewArtifactRouter(assetVersionRouter, new(controllers.ArtifactController), artifactRepo, assetRepo)
	NewExternalReferenceRouter(assetVersionRouter, new(controllers.ExternalReferenceController), assetRepo)

	return e
}

// publicVisitorAC returns an AccessControl mock where the user has no access
// to anything. Group-level read RBAC on a public resource will set
// IsPublicRequest=true, so DisallowPublicRequests blocks the request.
func publicVisitorAC() *mocks.AccessControl {
	ac := &mocks.AccessControl{}
	ac.On("HasAccess", mock.Anything, mock.Anything).Maybe().Return(false, nil)
	ac.On("IsAllowed", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(false, nil)
	ac.On("IsAllowedInProject", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(false, nil)
	ac.On("IsAllowedInAsset", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(false, nil)
	return ac
}

// readOnlyMemberAC returns an AccessControl mock where the user has ActionRead
// access everywhere but not ActionUpdate or ActionDelete. Group-level read RBAC
// will pass (IsPublicRequest stays false), but write-level RBAC checks deny.
func readOnlyMemberAC() *mocks.AccessControl {
	ac := &mocks.AccessControl{}
	ac.On("HasAccess", mock.Anything, mock.Anything).Maybe().Return(true, nil)

	// Org-level: allow read, deny everything else.
	ac.On("IsAllowed", mock.Anything, mock.Anything, mock.Anything, shared.ActionRead).Maybe().Return(true, nil)
	ac.On("IsAllowed", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(false, nil)

	// Project-level: allow read, deny write.
	ac.On("IsAllowedInProject", mock.Anything, mock.Anything, mock.Anything, shared.ActionRead, mock.Anything).Maybe().Return(true, nil)
	ac.On("IsAllowedInProject", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(false, nil)

	// Asset-level: allow read, deny write/delete.
	ac.On("IsAllowedInAsset", mock.Anything, mock.Anything, mock.Anything, shared.ActionRead, mock.Anything).Maybe().Return(true, nil)
	ac.On("IsAllowedInAsset", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return(false, nil)

	return ac
}

// TestNonGetRoutesBlockPublicRequests enforces that every non-GET route under
// /organizations blocks a public visitor (no membership at all).
func TestNonGetRoutesBlockPublicRequests(t *testing.T) {
	e := buildSecurityTestServer(t, publicVisitorAC())

	for _, route := range e.Routes() {
		method := route.Method
		path := route.Path

		if method == http.MethodGet || method == "echo_route_not_found" {
			continue
		}
		// Only test org-scoped routes (those with an :organization path parameter).
		// Routes like POST /api/v1/organizations/ (create org) sit above any
		// org RBAC, so IsPublicRequest can never be set for them — the
		// public-resource attack model does not apply there.
		if !strings.Contains(path, ":organization") {
			continue
		}
		if intentionallyPublicPaths[path] {
			continue
		}

		filledPath := fillParams(path)

		t.Run(method+" "+route.Path, func(t *testing.T) {
			req := httptest.NewRequest(method, filledPath, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			assert.Less(t, rec.Code, 500,
				"route %s %s reached its handler without write-level authorization "+
					"(status %d); add DisallowPublicRequests or a write-action RBAC middleware",
				method, route.Path, rec.Code,
			)
		})
	}
}

// TestReadOnlyMemberCannotWriteToProtectedRoutes enforces that every non-GET
// route requiring explicit write permission still blocks a read-only member
// (has ActionRead access, but not ActionUpdate or ActionDelete).
//
// Routes listed in memberOnlyPaths are skipped: those routes intentionally
// grant access to any authenticated member via DisallowPublicRequests.
func TestReadOnlyMemberCannotWriteToProtectedRoutes(t *testing.T) {
	e := buildSecurityTestServer(t, readOnlyMemberAC())

	for _, route := range e.Routes() {
		method := route.Method
		path := route.Path

		if method == http.MethodGet || method == "echo_route_not_found" {
			continue
		}
		if !strings.Contains(path, ":organization") {
			continue
		}
		if intentionallyPublicPaths[path] {
			continue
		}
		// Member-only routes are intentionally accessible to read-only members;
		// they are tested for public-visitor blocking in the first test.
		if memberOnlyPaths[method+" "+path] {
			continue
		}

		filledPath := fillParams(path)

		t.Run(method+" "+route.Path, func(t *testing.T) {
			req := httptest.NewRequest(method, filledPath, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			assert.Less(t, rec.Code, 500,
				"route %s %s reached its handler for a read-only member "+
					"(status %d); add a write-action RBAC middleware (e.g. assetScopedRBAC ActionUpdate)",
				method, route.Path, rec.Code,
			)
		})
	}
}
