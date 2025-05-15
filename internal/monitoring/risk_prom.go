// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var RecalculateRiskDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_daemon_recalculate_risk_amount",
	Help: "The total number of recalculating risk daemon operations",
})

var RecalculateAllRawRiskAssessmentsDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_recalculate_all_raw_risk_assessments_duration_minutes",
	Help:    "Duration of recalculating all raw risk assessments in minutes",
	Buckets: prometheus.DefBuckets,
})

var RecalculateAllRawRiskAssessmentsAssetVersionsAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_recalculate_all_raw_risk_assessments_asset_versions_amount",
	Help: "The total number of recalculating all raw risk assessments for asset versions",
})

var RecalculateAllRawRiskAssessmentsAssetVersionsUpdatedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_recalculate_all_raw_risk_assessments_asset_versions_updated_amount",
	Help: "The total number of recalculating all raw risk assessments for asset versions updated",
})
