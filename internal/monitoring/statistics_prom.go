// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var StatisticsUpdateDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_daemon_statistics_update_amount",
	Help: "The total number of statistics update operations",
})

var StatisticsUpdateDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_statistics_update_duration_minutes",
	Help:    "Duration of statistics updates in minutes",
	Buckets: prometheus.DefBuckets,
})

var AssetVersionsStatisticsAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_daemon_asset_versions_statistics_amount",
	Help: "The total number of asset versions statistics",
})
var AssetVersionsStatisticsSuccess = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_daemon_asset_versions_statistics_success",
	Help: "The total number of successful asset versions statistics",
})
