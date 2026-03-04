// Copyright 2024 CAPSLOCK
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/C4PSL0CK/capslock-operator/internal/health"
)

// setupPrometheusMetrics initializes Prometheus metrics collection and HTTP server
// Call this function during operator initialization (in main())
//
// Example usage in main():
//   setupPrometheusMetrics()
//
// Metrics will be exposed at http://0.0.0.0:8082/metrics
func setupPrometheusMetrics() error {
	log := log.Log.WithName("prometheus-setup")

	// Initialize metrics collector
	collector := health.InitializeMetrics()
	if collector == nil {
		return fmt.Errorf("failed to initialize metrics collector")
	}

	log.Info("Prometheus metrics collector initialized")

	// Start metrics HTTP server in background goroutine
	go func() {
		// Register Prometheus HTTP handler
		http.Handle("/metrics", promhttp.Handler())

		// Add health endpoint for liveness checks
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})

		// Listen on port 8082 (avoid conflict with default 8080)
		address := "0.0.0.0:8082"
		log.Info("Starting Prometheus metrics server", "address", address)

		if err := http.ListenAndServe(address, nil); err != nil && err != http.ErrServerClosed {
			log.Error(err, "Prometheus metrics server error")
		}
	}()

	return nil
}

// recordMetricsExample shows how to use the metrics collector in the operator
// This is a documentation example - actual calls should be in controller.go reconcile loop
func recordMetricsExample() {
	collector := health.GetCollector()

	// Record overall health score (0-100)
	collector.RecordHealthScore(85.5)

	// Record component scores
	collector.RecordReadinessScore(90.0)
	collector.RecordLatencyScore(88.0)
	collector.RecordSignatureFreshnessScore(92.0)
	collector.RecordErrorRateScore(95.0)
	collector.RecordResourceUsageScore(80.0)
	collector.RecordQueueDepthScore(85.0)

	// Record operational metrics
	collector.RecordCurrentReplicas(3)
	collector.RecordScalingEvent()

	// Record context
	collector.RecordTrafficPattern(0) // 0=normal, 1=spike, 2=sustained_high
	collector.RecordThreatLevel(0)    // 0=normal, 1=elevated
}
