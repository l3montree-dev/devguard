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
