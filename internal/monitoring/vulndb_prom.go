// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var VulnDBUpdateDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_vulndb_update_amount",
	Help: "The total number of vulndb update operations",
})

var VulnDBUpdateDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_vulndb_update_duration_minutes",
	Help:    "Duration of vulndb updates in minutes",
	Buckets: prometheus.DefBuckets,
})

var UpdateComponentPropertiesDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_update_component_properties_daemon_amount",
	Help: "The total number of update component properties daemon operations",
})

var UpdateComponentPropertiesDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_update_component_properties_duration_seconds",
	Help:    "Duration of update component properties in seconds",
	Buckets: prometheus.DefBuckets,
})

var DependencyVulnsAmount = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "devguard_dependency_vulns_amount",
	Help: "The total number of dependency vulnerabilities",
})

var DependencyVulnsUpdatedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_dependency_vulns_updated_amount",
	Help: "The total number of updated dependency vulnerabilities",
})
