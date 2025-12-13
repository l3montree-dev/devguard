// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

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
