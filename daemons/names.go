package daemons

// Daemon keys. They are persisted as config keys to track the last run time - do not rename.
const (
	DaemonVEXRuleRecommendations       = "vexrules.recommendations"
	DaemonCleanupOrphanedRecords       = "maintain.cleanup"
	DaemonSBOMGarbageCollection        = "maintain.sbomGarbageCollection"
	DaemonOpenSourceInsights           = "vulndb.opensourceinsights"
	DaemonVulnDB                       = "vulndb.vulndb"
	DaemonFixedVersions                = "vulndb.fixedVersions"
	DaemonDirectDependencyFixedVersion = "vulndb.directDependencyFixedVersion"
	DaemonAssetPipeline                = "assetPipeline"
	DaemonExternalEntityGarbage        = "externalEntityGarbageCollection"
)

// Asset pipeline stage names. They can be passed via DebugOptions.LimitToStages.
const (
	StageResolveFixedVersions              = "ResolveFixedVersions"
	StageSyncTickets                       = "SyncTickets"
	StageResolveDifferencesInTicketState   = "ResolveDifferencesInTicketState"
	StageScanAsset                         = "ScanAsset"
	StageSyncUpstream                      = "SyncUpstream"
	StageApplyVEXRules                     = "ApplyVEXRules"
	StageCollectStats                      = "CollectStats"
	StageRecalculateRiskForVulnerabilities = "RecalculateRiskForVulnerabilities"
	StageAutoReopenTickets                 = "AutoReopenTickets"
	StageDeleteOldAssetVersions            = "DeleteOldAssetVersions"
)
