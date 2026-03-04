package health

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusMetrics holds all Prometheus metric objects for the ICAP operator
type PrometheusMetrics struct {
	healthScore                prometheus.Gauge
	readinessScore             prometheus.Gauge
	latencyScore               prometheus.Gauge
	signatureFreshnessScore    prometheus.Gauge
	errorRateScore             prometheus.Gauge
	resourceUsageScore         prometheus.Gauge
	queueDepthScore            prometheus.Gauge
	currentReplicas            prometheus.Gauge
	scalingEventsTotal         prometheus.Counter
	contextTrafficPattern      prometheus.Gauge
	contextThreatLevel         prometheus.Gauge
	mu                         sync.Mutex
}

var metrics *PrometheusMetrics
var once sync.Once

// InitializeMetrics initializes all Prometheus metrics for the operator
func InitializeMetrics() *PrometheusMetrics {
	once.Do(func() {
		metrics = &PrometheusMetrics{
			healthScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_score",
				Help: "Current overall health score of the ICAP service (0-100)",
			}),
			readinessScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_readiness_score",
				Help: "Readiness component of health score (0-100)",
			}),
			latencyScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_latency_score",
				Help: "Latency component of health score (0-100)",
			}),
			signatureFreshnessScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_signature_freshness_score",
				Help: "Signature freshness component of health score (0-100)",
			}),
			errorRateScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_error_rate_score",
				Help: "Error rate component of health score (0-100)",
			}),
			resourceUsageScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_resource_usage_score",
				Help: "Resource usage component of health score (0-100)",
			}),
			queueDepthScore: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_health_queue_depth_score",
				Help: "Queue depth component of health score (0-100)",
			}),
			currentReplicas: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_deployment_current_replicas",
				Help: "Current number of ICAP operator replicas",
			}),
			scalingEventsTotal: promauto.NewCounter(prometheus.CounterOpts{
				Name: "icapoperator_deployment_scaling_events_total",
				Help: "Total number of scaling events triggered",
			}),
			contextTrafficPattern: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_context_traffic_pattern",
				Help: "Current traffic pattern: 0=normal, 1=spike, 2=sustained",
			}),
			contextThreatLevel: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "icapoperator_context_threat_level",
				Help: "Current threat level: 0=normal, 1=elevated, 2=critical",
			}),
		}
	})
	return metrics
}

// RecordHealthScore records the overall health score
func (m *PrometheusMetrics) RecordHealthScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthScore.Set(score)
}

// RecordReadinessScore records the readiness component score
func (m *PrometheusMetrics) RecordReadinessScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readinessScore.Set(score)
}

// RecordLatencyScore records the latency component score
func (m *PrometheusMetrics) RecordLatencyScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencyScore.Set(score)
}

// RecordSignatureFreshnessScore records the signature freshness component score
func (m *PrometheusMetrics) RecordSignatureFreshnessScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signatureFreshnessScore.Set(score)
}

// RecordErrorRateScore records the error rate component score
func (m *PrometheusMetrics) RecordErrorRateScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorRateScore.Set(score)
}

// RecordResourceUsageScore records the resource usage component score
func (m *PrometheusMetrics) RecordResourceUsageScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resourceUsageScore.Set(score)
}

// RecordQueueDepthScore records the queue depth component score
func (m *PrometheusMetrics) RecordQueueDepthScore(score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueDepthScore.Set(score)
}

// RecordCurrentReplicas records the current replica count
func (m *PrometheusMetrics) RecordCurrentReplicas(replicas int32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentReplicas.Set(float64(replicas))
}

// IncrementScalingEvents increments the scaling events counter
func (m *PrometheusMetrics) IncrementScalingEvents() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scalingEventsTotal.Inc()
}

// RecordTrafficPattern records the current traffic pattern context
func (m *PrometheusMetrics) RecordTrafficPattern(pattern float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.contextTrafficPattern.Set(pattern)
}

// RecordThreatLevel records the current threat level context
func (m *PrometheusMetrics) RecordThreatLevel(level float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.contextThreatLevel.Set(level)
}

// GetMetrics returns the global metrics instance
func GetMetrics() *PrometheusMetrics {
	if metrics == nil {
		return InitializeMetrics()
	}
	return metrics
}
