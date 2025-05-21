// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var SyncTicketDaemonAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_daemon_assets_sync_tickets_amount",
	Help: "The total number of asset sync tickets operations",
})

var SyncTicketDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "devguard_daemon_assets_sync_tickets_duration_minutes",
	Help:    "Duration of asset sync tickets in minutes",
	Buckets: prometheus.DefBuckets,
})

var TicketCreatedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_ticket_created_amount",
	Help: "The total number of tickets created",
})

var TicketUpdatedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_ticket_updated_amount",
	Help: "The total number of tickets updated",
})

var TicketReopenedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_ticket_reopened_amount",
	Help: "The total number of tickets reopened",
})

var TicketClosedAmount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "devguard_ticket_closed_amount",
	Help: "The total number of tickets closed",
})
