/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/senali/capslock-operator/api/v1alpha1"
)

// AdaptiveScalingManager handles health-score-based auto-scaling
type AdaptiveScalingManager struct {
	minReplicas       int32
	maxReplicas       int32
	targetHealthScore int32
	scalingThreshold  float64
}

// performAdaptiveScaling adjusts replicas based on health score vs target score
// This implements the auto-scaling logic from the proposal
func (r *ICAPServiceReconciler) performAdaptiveScaling(ctx context.Context, icapService *securityv1alpha1.ICAPService) error {
	logger := log.FromContext(ctx)

	// Get current deployment
	deployment := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      icapService.Name + "-deployment",
		Namespace: icapService.Namespace,
	}, deployment)
	if err != nil {
		return err
	}

	// Initialize scaling manager with policy from spec
	manager := &AdaptiveScalingManager{
		minReplicas:       icapService.Spec.ScalingPolicy.MinReplicas,
		maxReplicas:       icapService.Spec.ScalingPolicy.MaxReplicas,
		targetHealthScore: icapService.Spec.ScalingPolicy.TargetHealthScore,
		scalingThreshold:  0.05, // 5% deviation triggers scaling
	}

	// Get current health score from status
	currentScore := icapService.Status.CurrentHealthScore
	desiredReplicas := *deployment.Spec.Replicas

	// Decision logic: scale based on health score deviation
	scoreDifference := float64(manager.targetHealthScore - currentScore)
	scoreDeviation := scoreDifference / float64(manager.targetHealthScore)

	logger.Info("Adaptive scaling check",
		"currentScore", currentScore,
		"targetScore", manager.targetHealthScore,
		"deviation", fmt.Sprintf("%.2f%%", scoreDeviation*100),
		"currentReplicas", desiredReplicas,
	)

	// Scale up if health score is significantly below target
	if scoreDeviation > manager.scalingThreshold && desiredReplicas < manager.maxReplicas {
		desiredReplicas = min(desiredReplicas+1, manager.maxReplicas)
		logger.Info("Scaling UP due to low health score",
			"reason", fmt.Sprintf("health %.0f < target %.0f", float64(currentScore), float64(manager.targetHealthScore)),
			"newReplicas", desiredReplicas,
		)
	}

	// Scale down if health score is significantly above target AND safe to do so
	if scoreDeviation < -manager.scalingThreshold && desiredReplicas > manager.minReplicas {
		desiredReplicas = max(desiredReplicas-1, manager.minReplicas)
		logger.Info("Scaling DOWN due to high health score",
			"reason", fmt.Sprintf("health %.0f > target %.0f", float64(currentScore), float64(manager.targetHealthScore)),
			"newReplicas", desiredReplicas,
		)
	}

	// Apply scaling if needed
	if desiredReplicas != *deployment.Spec.Replicas {
		deployment.Spec.Replicas = &desiredReplicas
		if err := r.Update(ctx, deployment); err != nil {
			logger.Error(err, "Failed to update deployment replicas")
			return err
		}
		// Update ICAPService spec to track the change
		icapService.Spec.Replicas = desiredReplicas
		if err := r.Update(ctx, icapService); err != nil {
			logger.Error(err, "Failed to update ICAPService spec")
			return err
		}
		logger.Info("Adaptive scaling applied successfully", "newReplicas", desiredReplicas)
	}

	return nil
}

// Helper functions
func min(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
