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

var FirstPartyScanAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_first_party_scan_amount",
	Help: "The total number of first party scans",
})

var DependencyVulnScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_dependency_vuln_scan_duration_seconds",
	Help:    "Duration of dependency vulnerability scans in seconds",
	Buckets: prometheus.DefBuckets,
})
var FirstPartyScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_first_party_scan_duration_seconds",
	Help:    "Duration of first party scans in seconds",
	Buckets: prometheus.DefBuckets,
})
