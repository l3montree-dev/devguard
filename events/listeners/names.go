package listeners

// Daemon keys - they identify the daemons in the CLI and the admin endpoints.
// The admin endpoints persist them as config keys for their cooldown - do not rename.
const (
	DaemonVEXRuleRecommendations    = "vexrules.recommendations"
	DaemonVEXRuleExchangeSubmit     = "vexrules.exchange.submit"
	DaemonVEXRuleExchangeFetch      = "vexrules.exchange.fetch"
	DaemonSBOMGarbageCollection     = "maintain.sbomGarbageCollection"
	DaemonOpenSourceInsights        = "vulndb.opensourceinsights"
	DaemonVulnDB                    = "vulndb.vulndb"
	DaemonFixedVersions             = "vulndb.fixedVersions"
	DaemonAssetPipeline             = "assetPipeline"
	DaemonAssetPipelineAll          = "daemon.assetPipelineAll"
	DaemonAssetPipelineSinglePrefix = "daemon.assetPipelineSingle."
	DaemonExternalEntityGarbage     = "externalEntityGarbageCollection"
)

// Asset pipeline stage names. They can be passed via DebugOptions.LimitToStages.
const (
	StageResolveFixedVersions              = "ResolveFixedVersions"
	StageSyncTickets                       = "SyncTickets"
	StageResolveDifferencesInTicketState   = "ResolveDifferencesInTicketState"
	StageScanAsset                         = "ScanAsset"
	StageSyncUpstream                      = "SyncUpstream"
	StageResolveLicenses                   = "ResolveLicenses"
	StageFindLicenseRisks                  = "FindLicenseRisks"
	StageApplyVEXRules                     = "ApplyVEXRules"
	StageCollectStats                      = "CollectStats"
	StageRecalculateRiskForVulnerabilities = "RecalculateRiskForVulnerabilities"
	StageDeleteOldAssetVersions            = "DeleteOldAssetVersions"
)
