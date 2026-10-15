package listeners

// Daemon keys. They are persisted as config keys to track the last run time - do not rename.
const (
	DaemonVEXRuleRecommendations       = "vexrules.recommendations"
	DaemonCleanupOrphanedRecords       = "maintain.cleanup"
	DaemonSBOMGarbageCollection        = "maintain.sbomGarbageCollection"
	DaemonOpenSourceInsights           = "vulndb.opensourceinsights"
	DaemonVulnDB                       = "vulndb.vulndb"
	DaemonScan                         = "vulndb.scan"
	DaemonFixedVersions                = "vulndb.fixedVersions"
	DaemonDirectDependencyFixedVersion = "vulndb.directDependencyFixedVersion"
	DaemonAssetPipeline                = "assetPipeline"
	DaemonAssetPipelineAll             = "daemon.assetPipelineAll"
	DaemonAssetPipelineSinglePrefix    = "daemon.assetPipelineSingle."
	DaemonExternalEntityGarbage        = "externalEntityGarbageCollection"
)

// Asset pipeline stage names. They can be passed via DebugOptions.LimitToStages.
const (
	StageResolveFixedVersions              = "ResolveFixedVersions"
	StageSyncTickets                       = "SyncTickets"
	StageResolveDifferencesInTicketState   = "ResolveDifferencesInTicketState"
	StageScanAsset                         = "ScanAsset"
	StageSyncUpstream                      = "SyncUpstream"
	StageResolveLicenses                   = "ResolveLicenses"
	StageApplyVEXRules                     = "ApplyVEXRules"
	StageCollectStats                      = "CollectStats"
	StageRecalculateRiskForVulnerabilities = "RecalculateRiskForVulnerabilities"
	StageDeleteOldAssetVersions            = "DeleteOldAssetVersions"
)
