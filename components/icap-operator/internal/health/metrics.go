package health

import (
	"time"
)

// HealthMetrics represents all health dimensions
type HealthMetrics struct {
	// Individual component scores (0-100)
	ReadinessScore float64
	LatencyScore   float64
	SignatureScore float64
	ErrorScore     float64
	ResourceScore  float64
	QueueScore     float64

	// Overall weighted score
	OverallScore int32

	// Timestamp
	Timestamp time.Time

	// Derived diagnostics emitted to Prometheus
	SignatureAgeHours float64

	// Context information
	Context HealthContext
}

// HealthContext captures the current operational context
type HealthContext struct {
	TrafficPattern TrafficLevel
	ThreatLevel    ThreatLevel
	ResourceState  ResourceState
	TimeOfDay      string
}

// TrafficLevel indicates current traffic intensity
type TrafficLevel string

const (
	TrafficLow    TrafficLevel = "low"
	TrafficNormal TrafficLevel = "normal"
	TrafficHigh   TrafficLevel = "high"
	TrafficSpike  TrafficLevel = "spike"
)

// ThreatLevel indicates current threat environment
type ThreatLevel string

const (
	ThreatNormal   ThreatLevel = "normal"
	ThreatElevated ThreatLevel = "elevated"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

// ResourceState indicates resource availability
type ResourceState string

const (
	ResourceHealthy     ResourceState = "healthy"
	ResourceConstrained ResourceState = "constrained"
	ResourceCritical    ResourceState = "critical"
)

// AdaptiveWeights represents dynamic weight allocation
type AdaptiveWeights struct {
	Readiness  float64
	Latency    float64
	Signatures float64
	Errors     float64
	Resources  float64
	Queue      float64
}

// BaselineWeights are the default weights
var BaselineWeights = AdaptiveWeights{
	Readiness:  0.25,
	Latency:    0.25,
	Signatures: 0.20,
	Errors:     0.15,
	Resources:  0.10,
	Queue:      0.05,
}
