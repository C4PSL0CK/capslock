package health

import (
	securityv1alpha1 "github.com/senali/capslock-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	"math"
	"time"
)

// CalculateHealth computes comprehensive adaptive health score
func CalculateHealth(
	deployment *appsv1.Deployment,
	icapService *securityv1alpha1.ICAPService,
) HealthMetrics {

	// Analyze current context
	context := AnalyzeContext(deployment)

	// Calculate individual component scores
	metrics := HealthMetrics{
		ReadinessScore: calculateReadiness(deployment),
		LatencyScore:   calculateLatency(icapService, context),
		SignatureScore: calculateSignatureFreshness(),
		ErrorScore:     calculateErrorHealth(context),
		ResourceScore:  calculateResourceHealth(deployment),
		QueueScore:     calculateQueueHealth(deployment, context),
		Timestamp:      time.Now(),
		Context:        context,
	}

	// Calculate adaptive weights
	weights := CalculateAdaptiveWeights(context)

	// Compute weighted overall score
	metrics.OverallScore = CalculateWeightedScore(metrics, weights)

	return metrics
}

// calculateReadiness measures pod availability
func calculateReadiness(deployment *appsv1.Deployment) float64 {
	if deployment.Status.Replicas == 0 {
		return 0
	}

	ready := float64(deployment.Status.ReadyReplicas)
	desired := float64(deployment.Status.Replicas)

	score := (ready / desired) * 100

	// Penalty for unavailable replicas
	if deployment.Status.UnavailableReplicas > 0 {
		penalty := float64(deployment.Status.UnavailableReplicas) / desired * 20
		score -= penalty
	}

	return math.Max(0, score)
}

// calculateLatency simulates scan latency health
func calculateLatency(icapService *securityv1alpha1.ICAPService, context HealthContext) float64 {
	// Simulate latency based on thresholds and traffic
	maxLatency := icapService.Spec.HealthThresholds.MaxLatency

	// Base score from threshold
	var baseScore float64
	switch maxLatency {
	case "500ms":
		baseScore = 100
	case "1s":
		baseScore = 90
	case "2s":
		baseScore = 70
	default:
		baseScore = 50
	}

	// Adjust for traffic (high traffic = higher latency)
	switch context.TrafficPattern {
	case TrafficSpike:
		baseScore -= 15
	case TrafficHigh:
		baseScore -= 10
	case TrafficLow:
		baseScore += 5
	}

	return math.Max(0, math.Min(100, baseScore))
}

// calculateSignatureFreshness checks virus signature age
func calculateSignatureFreshness() float64 {
	// Simulate signature age
	// In production: Query ClamAV for actual signature timestamp
	simulatedAge := 8 * time.Hour

	if simulatedAge < 6*time.Hour {
		return 100
	} else if simulatedAge < 12*time.Hour {
		return 90
	} else if simulatedAge < 24*time.Hour {
		return 75
	} else if simulatedAge < 48*time.Hour {
		return 50
	}
	return 25
}

// calculateErrorHealth measures scan reliability
func calculateErrorHealth(context HealthContext) float64 {
	// Simulate error rate based on context
	// In production: Track actual scan failures

	baseErrorRate := 0.02 // 2% base error rate

	// Higher errors under stress
	switch context.TrafficPattern {
	case TrafficSpike:
		baseErrorRate += 0.03
	case TrafficHigh:
		baseErrorRate += 0.01
	}

	switch context.ResourceState {
	case ResourceCritical:
		baseErrorRate += 0.05
	case ResourceConstrained:
		baseErrorRate += 0.02
	}

	// Convert to score (lower error = higher score)
	score := (1 - baseErrorRate) * 100
	return math.Max(0, math.Min(100, score))
}

// calculateResourceHealth measures resource efficiency
func calculateResourceHealth(deployment *appsv1.Deployment) float64 {
	// Simulate resource health
	// In production: Check actual CPU/Memory usage from metrics

	if deployment.Status.ReadyReplicas == deployment.Status.Replicas &&
		deployment.Status.UnavailableReplicas == 0 {
		return 95 // Healthy
	}

	if deployment.Status.UnavailableReplicas > 0 {
		return 60 // Constrained
	}

	return 80 // Acceptable
}

// calculateQueueHealth measures scan backlog
func calculateQueueHealth(deployment *appsv1.Deployment, context HealthContext) float64 {
	// Simulate queue depth based on replicas and traffic
	// In production: Monitor actual ICAP queue metrics

	replicas := float64(deployment.Status.Replicas)

	var simulatedQueue float64
	switch context.TrafficPattern {
	case TrafficSpike:
		simulatedQueue = replicas * 50 // High backlog
	case TrafficHigh:
		simulatedQueue = replicas * 20
	case TrafficNormal:
		simulatedQueue = replicas * 5
	default:
		simulatedQueue = replicas * 1
	}

	// Assume max healthy queue = replicas * 30
	maxHealthyQueue := replicas * 30

	if simulatedQueue <= maxHealthyQueue {
		return 100
	}

	// Degrading score as queue grows
	score := 100 - ((simulatedQueue - maxHealthyQueue) / maxHealthyQueue * 100)
	return math.Max(0, score)
}
