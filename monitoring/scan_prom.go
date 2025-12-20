// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later
package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var DependencyVulnScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_dependency_vuln_scan_duration_minutes",
	Help:    "Duration of dependency vulnerability scans in minutes",
	Buckets: prometheus.DefBuckets,
})

var FirstPartyScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_first_party_scan_duration_minutes",
	Help:    "Duration of first party scans in minutes",
	Buckets: prometheus.DefBuckets,
})

var ScanDaemonDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_asset_version_scan_duration_minutes",
	Help:    "Duration of asset version scans in minutes",
	Buckets: prometheus.DefBuckets,
})
