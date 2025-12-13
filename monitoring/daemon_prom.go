// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var RecalculateRawRiskAssessmentsDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_recalculate_raw_risk_assessments_duration_minutes",
	Help:    "Duration of recalculating raw risk assessments in minutes",
	Buckets: prometheus.DefBuckets,
})

var UpstreamSyncDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_upstream_sync_duration_minutes",
	Help:    "Duration of upstream sync operations in minutes",
	Buckets: prometheus.DefBuckets,
})

var VulnDBUpdateDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_vulndb_update_duration_minutes",
	Help:    "Duration of vulndb updates in minutes",
	Buckets: prometheus.DefBuckets,
})

var UpdateComponentPropertiesDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_update_component_properties_duration_minutes",
	Help:    "Duration of update component properties in minutes",
	Buckets: prometheus.DefBuckets,
})

var SyncTicketDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_assets_sync_tickets_duration_minutes",
	Help:    "Duration of asset sync tickets in minutes",
	Buckets: prometheus.DefBuckets,
})

var StatisticsUpdateDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_statistics_update_duration_minutes",
	Help:    "Duration of statistics updates in minutes",
	Buckets: prometheus.DefBuckets,
})

var UpdateOpenSourceInsightInformationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_update_deps_dev_information_duration_minutes",
	Help:    "Duration of update deps.dev information daemon operations in minutes",
	Buckets: prometheus.DefBuckets,
})

var OpenSourceInsightProjectAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_deps_dev_project_amount",
	Help: "The total number of deps.dev projects",
})

var OpenSourceInsightProjectUpdatedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_deps_dev_project_updated_amount",
	Help: "The total number of updated deps.dev projects",
})

var FetchAssetStageDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_fetch_asset_stage_duration_minutes",
	Help:    "Duration of fetch asset stage in minutes",
	Buckets: prometheus.DefBuckets,
})

var ReopenVulnsStageDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_reopen_vulns_stage_duration_minutes",
	Help:    "Duration of reopen vulns stage in minutes",
	Buckets: prometheus.DefBuckets,
})
