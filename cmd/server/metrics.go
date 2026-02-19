// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	authCalloutRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nats_auth_callout_requests_total",
			Help: "Total number of auth callout requests",
		},
		[]string{"status"}, // "authorized", "denied", "error"
	)

	authCalloutDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "nats_auth_callout_duration_seconds",
			Help:    "Duration of auth callout request processing",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0},
		},
	)

	authServiceUp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "nats_auth_service_up",
			Help: "Whether the auth service is connected to NATS (1=up, 0=down)",
		},
	)
)
