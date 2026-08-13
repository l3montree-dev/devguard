package router

import "go.uber.org/fx"

// Routers lets a single fx.Invoke force construction of every router at once
// (route registration is a side effect of each NewXRouter constructor).
type Routers struct {
	fx.In

	Admin                        AdminRouter
	APIV1                        APIV1Router
	APIV2                        APIV2Router
	Artifact                     ArtifactRouter
	Asset                        AssetRouter
	AssetVersion                 AssetVersionRouter
	CompliancePosture            CompliancePostureRouter
	ComplianceComponent          ComplianceComponentRouter
	ComplianceComponentStatement ComplianceComponentStatementRouter
	DependencyVuln               DependencyVulnRouter
	FirstPartyVuln               FirstPartyVulnRouter
	LicenseRisk                  LicenseRiskRouter
	Org                          OrgRouter
	Project                      ProjectRouter
	Session                      SessionRouter
	Share                        ShareRouter
	VulnDB                       VulnDBRouter
	DependencyProxy              DependencyProxyRouter
	OCIRegistry                  OCIRegistryRouter
	VEXRule                      VEXRuleRouter
	ExternalReference            ExternalReferenceRouter
	Advisory                     AdvisoryRouter
}

var RouterModule = fx.Options(
	fx.Provide(NewAdminRouter),
	fx.Provide(NewAPIV1Router),
	fx.Provide(NewAPIV2Router),
	fx.Provide(NewArtifactRouter),
	fx.Provide(NewAssetRouter),
	fx.Provide(NewAssetVersionRouter),
	fx.Provide(NewCompliancePostureRouter),
	fx.Provide(NewComplianceComponentRouter),
	fx.Provide(NewComplianceComponentStatementRouter),
	fx.Provide(NewDependencyVulnRouter),
	fx.Provide(NewFirstPartyVulnRouter),
	fx.Provide(NewLicenseRiskRouter),
	fx.Provide(NewOrgRouter),
	fx.Provide(NewProjectRouter),
	fx.Provide(NewSessionRouter),
	fx.Provide(NewShareRouter),
	fx.Provide(NewVulnDBRouter),
	fx.Provide(NewDependencyProxyRouter),
	fx.Provide(NewOCIRegistryRouter),
	fx.Provide(NewVEXRuleRouter),
	fx.Provide(NewExternalReferenceRouter),
	fx.Provide(NewAdvisoryRouter),
)
