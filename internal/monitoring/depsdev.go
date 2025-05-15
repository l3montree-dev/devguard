// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var UpdateDepsDevInformationDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_update_deps_dev_information_daemon_amount",
	Help: "The total number of update deps.dev information daemon operations",
})
var UpdateDepsDevInformationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_update_deps_dev_information_duration_minutes",
	Help:    "Duration of update deps.dev information in minutes",
	Buckets: prometheus.DefBuckets,
})

var DepsDevProjectAmount = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "devguard_deps_dev_project_amount",
	Help: "The total number of deps.dev projects",
})

var DepsDevProjectUpdatedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_deps_dev_project_updated_amount",
	Help: "The total number of updated deps.dev projects",
})
