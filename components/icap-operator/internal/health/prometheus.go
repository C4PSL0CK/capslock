package health

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Prometheus metrics for the ICAP Operator.
// These are the metrics referenced by the Grafana dashboard and alerting rules.
var (
	HealthScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "capslock_icap_health_score",
			Help: "Overall adaptive health score for an ICAPService (0-100).",
		},
		[]string{"service"},
	)

	ThreatsDetectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "capslock_icap_threats_detected_total",
			Help: "Total number of threats detected by ClamAV, by service and threat type.",
		},
		[]string{"service", "threat_type"},
	)

	ClamAVSignatureAgeHours = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "capslock_icap_clamav_signature_age_hours",
			Help: "Age of the ClamAV virus signature database in hours.",
		},
		[]string{"service"},
	)

	ScanDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "capslock_icap_scan_duration_seconds",
			Help:    "ICAP scan request duration in seconds.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"service"},
	)

	CoverageScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "capslock_icap_coverage_score",
			Help: "Fraction of traffic covered by ICAP scanning (0-100).",
		},
		[]string{"service"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		HealthScore,
		ThreatsDetectedTotal,
		ClamAVSignatureAgeHours,
		ScanDurationSeconds,
		CoverageScore,
	)
}

// EmitMetrics publishes the computed HealthMetrics to Prometheus.
// Call this once per reconciliation cycle after CalculateHealth returns.
func EmitMetrics(m HealthMetrics, serviceName string) {
	HealthScore.WithLabelValues(serviceName).Set(float64(m.OverallScore))
	ClamAVSignatureAgeHours.WithLabelValues(serviceName).Set(m.SignatureAgeHours)

	// Coverage score: use the readiness proportion as a proxy for scan coverage.
	// (100% ready replicas → 100% coverage; degraded replicas → proportionally less.)
	CoverageScore.WithLabelValues(serviceName).Set(m.ReadinessScore)
}
