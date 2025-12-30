package health

import (
	"math"
)

// CalculateAdaptiveWeights adjusts weights based on context
func CalculateAdaptiveWeights(context HealthContext) AdaptiveWeights {
	// Start with baseline weights
	weights := BaselineWeights

	// Adjust based on traffic pattern
	weights = adjustForTraffic(weights, context.TrafficPattern)

	// Adjust based on threat level
	weights = adjustForThreat(weights, context.ThreatLevel)

	// Adjust based on resource state
	weights = adjustForResources(weights, context.ResourceState)

	// Normalize to ensure weights sum to 1.0
	weights = normalizeWeights(weights)

	return weights
}

// adjustForTraffic modifies weights based on traffic level
func adjustForTraffic(w AdaptiveWeights, traffic TrafficLevel) AdaptiveWeights {
	switch traffic {
	case TrafficSpike, TrafficHigh:
		// High traffic: Prioritize latency and queue management
		w.Latency += 0.10
		w.Queue += 0.05
		w.Signatures -= 0.10
		w.Errors -= 0.05

	case TrafficLow:
		// Low traffic: Good time to update signatures
		w.Signatures += 0.10
		w.Latency -= 0.05
		w.Queue -= 0.05
	}
	return w
}

// adjustForThreat modifies weights based on threat level
func adjustForThreat(w AdaptiveWeights, threat ThreatLevel) AdaptiveWeights {
	switch threat {
	case ThreatCritical, ThreatHigh:
		// High threat: Prioritize detection quality
		w.Signatures += 0.15
		w.Errors += 0.10
		w.Latency -= 0.15
		w.Queue -= 0.10

	case ThreatElevated:
		// Elevated threat: Balance detection and performance
		w.Signatures += 0.08
		w.Errors += 0.05
		w.Latency -= 0.08
		w.Queue -= 0.05
	}
	return w
}

// adjustForResources modifies weights based on resource availability
func adjustForResources(w AdaptiveWeights, resources ResourceState) AdaptiveWeights {
	switch resources {
	case ResourceCritical, ResourceConstrained:
		// Resource pressure: Prioritize efficiency and readiness
		w.Resources += 0.15
		w.Readiness += 0.10
		w.Latency -= 0.15
		w.Signatures -= 0.10
	}
	return w
}

// normalizeWeights ensures weights sum to 1.0
func normalizeWeights(w AdaptiveWeights) AdaptiveWeights {
	total := w.Readiness + w.Latency + w.Signatures +
		w.Errors + w.Resources + w.Queue

	if total == 0 {
		return BaselineWeights
	}

	return AdaptiveWeights{
		Readiness:  w.Readiness / total,
		Latency:    w.Latency / total,
		Signatures: w.Signatures / total,
		Errors:     w.Errors / total,
		Resources:  w.Resources / total,
		Queue:      w.Queue / total,
	}
}

// CalculateWeightedScore computes final score with adaptive weights
func CalculateWeightedScore(metrics HealthMetrics, weights AdaptiveWeights) int32 {
	score := (metrics.ReadinessScore * weights.Readiness) +
		(metrics.LatencyScore * weights.Latency) +
		(metrics.SignatureScore * weights.Signatures) +
		(metrics.ErrorScore * weights.Errors) +
		(metrics.ResourceScore * weights.Resources) +
		(metrics.QueueScore * weights.Queue)

	// Clamp between 0 and 100
	return int32(math.Max(0, math.Min(100, score)))
}
