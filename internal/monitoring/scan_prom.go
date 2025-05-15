// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later
package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var DependencyVulnScanAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_dependency_vuln_scan_amount",
	Help: "The total number of dependency vulnerability scans",
})

var DependencyVulnScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_dependency_vuln_scan_duration_minutes",
	Help:    "Duration of dependency vulnerability scans in minutes",
	Buckets: prometheus.DefBuckets,
})

var FirstPartyScanAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_first_party_scan_amount",
	Help: "The total number of first party scans",
})

var FirstPartyScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_first_party_scan_duration_minutes",
	Help:    "Duration of first party scans in minutes",
	Buckets: prometheus.DefBuckets,
})

var ScansDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_scans_daemon_amount",
	Help: "The total number of scans daemon",
})

var ScansDaemonDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_asset_version_scan_duration_minutes",
	Help:    "Duration of asset version scans in minutes",
	Buckets: prometheus.DefBuckets,
})

var AssetVersionScanAmount = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "devguard_asset_version_scan_amount",
	Help: "The total number of asset version",
})

var AssetVersionScanSuccess = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_asset_version_scan_success",
	Help: "The total number of successful asset version scans",
})
