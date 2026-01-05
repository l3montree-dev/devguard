// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later
package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var MaliciousPackageBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "devguard_malicious_package_blocked_total",
	Help: "Total number of malicious packages blocked by the dependency proxy",
}, []string{"ecosystem", "package"})

var DependencyProxyRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "devguard_dependency_proxy_request_duration_seconds",
	Help:    "Duration of dependency proxy requests in seconds",
	Buckets: prometheus.DefBuckets,
}, []string{"ecosystem"})
