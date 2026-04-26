package health

import (
	appsv1 "k8s.io/api/apps/v1"
	"time"
)

// AnalyzeContext determines the current operational context
func AnalyzeContext(deployment *appsv1.Deployment) HealthContext {
	context := HealthContext{
		TrafficPattern: analyzeTrafficPattern(deployment),
		ThreatLevel:    analyzeThreatLevel(),
		ResourceState:  analyzeResourceState(deployment),
		TimeOfDay:      getTimeCategory(),
	}
	return context
}

// analyzeTrafficPattern determines current traffic level
func analyzeTrafficPattern(deployment *appsv1.Deployment) TrafficLevel {
	// Simulate traffic analysis based on replica count and restart frequency
	// In production: Use actual request rate metrics from Prometheus

	replicas := deployment.Status.Replicas
	restarts := getRecentRestarts(deployment)

	if replicas >= 8 || restarts > 5 {
		return TrafficSpike
	} else if replicas >= 5 || restarts > 2 {
		return TrafficHigh
	} else if replicas >= 3 {
		return TrafficNormal
	}
	return TrafficLow
}

// analyzeThreatLevel determines current threat environment
func analyzeThreatLevel() ThreatLevel {
	// Simulate threat level analysis
	// In production: Integrate with threat intelligence feeds
	// For now: Time-based simulation (higher threat during business hours)

	hour := time.Now().Hour()

	// Business hours (9 AM - 5 PM) = higher threat
	if hour >= 9 && hour <= 17 {
		return ThreatElevated
	}

	return ThreatNormal
}

// analyzeResourceState checks resource availability
func analyzeResourceState(deployment *appsv1.Deployment) ResourceState {
	// Simulate resource state analysis
	// In production: Check actual cluster resource availability

	if deployment.Status.UnavailableReplicas > 0 {
		return ResourceConstrained
	}

	if deployment.Status.ReadyReplicas < deployment.Status.Replicas {
		return ResourceConstrained
	}

	return ResourceHealthy
}

// getTimeCategory returns time of day category
func getTimeCategory() string {
	hour := time.Now().Hour()

	if hour >= 6 && hour < 12 {
		return "morning"
	} else if hour >= 12 && hour < 18 {
		return "afternoon"
	} else if hour >= 18 && hour < 22 {
		return "evening"
	}
	return "night"
}

// getRecentRestarts counts container restarts
func getRecentRestarts(deployment *appsv1.Deployment) int32 {
	// Simplified: In production, track restart history over time window
	return deployment.Status.UnavailableReplicas
}
