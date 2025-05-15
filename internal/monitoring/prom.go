// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var DaemonStartedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_daemon_started_amount",
	Help: "The total number of daemon started",
})
var DaemonStartedDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_started_duration_minutes",
	Help:    "Duration of daemon started in minutes",
	Buckets: prometheus.DefBuckets,
})
