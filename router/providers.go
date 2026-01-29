package router

import "go.uber.org/fx"

var RouterModule = fx.Options(
	fx.Provide(NewAPIV1Router),
	fx.Provide(NewArtifactRouter),
	fx.Provide(NewAssetRouter),
	fx.Provide(NewAssetVersionRouter),
	fx.Provide(NewDependencyVulnRouter),
	fx.Provide(NewFirstPartyVulnRouter),
	fx.Provide(NewLicenseRiskRouter),
	fx.Provide(NewOrgRouter),
	fx.Provide(NewProjectRouter),
	fx.Provide(NewSessionRouter),
	fx.Provide(NewShareRouter),
	fx.Provide(NewVulnDBRouter),
	fx.Provide(NewDependencyProxyRouter),
	fx.Provide(NewFalsePositiveRuleRouter),
)
