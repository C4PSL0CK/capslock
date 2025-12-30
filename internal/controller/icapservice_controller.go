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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/senali/capslock-operator/api/v1alpha1"
	"github.com/senali/capslock-operator/internal/health"
)

// ICAPServiceReconciler reconciles a ICAPService object
type ICAPServiceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.capslock.io,resources=icapservices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.capslock.io,resources=icapservices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.capslock.io,resources=icapservices/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ICAPServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling ICAPService", "name", req.Name, "namespace", req.Namespace)

	// Fetch the ICAPService instance
	icapService := &securityv1alpha1.ICAPService{}
	err := r.Get(ctx, req.NamespacedName, icapService)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, could have been deleted
			logger.Info("ICAPService resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request
		logger.Error(err, "Failed to get ICAPService")
		return ctrl.Result{}, err
	}

	// Step 1: Create or update ICAP Deployment
	if err := r.reconcileDeployment(ctx, icapService); err != nil {
		logger.Error(err, "Failed to reconcile Deployment")
		return ctrl.Result{}, err
	}

	// Step 2: Create or update Service
	if err := r.reconcileService(ctx, icapService); err != nil {
		logger.Error(err, "Failed to reconcile Service")
		return ctrl.Result{}, err
	}

	// Step 3: Update status
	if err := r.updateStatus(ctx, icapService); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	logger.Info("Successfully reconciled ICAPService")
	// Requeue after 30 seconds to check health
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcileDeployment creates or updates the ICAP Deployment
func (r *ICAPServiceReconciler) reconcileDeployment(ctx context.Context, icapService *securityv1alpha1.ICAPService) error {
	logger := log.FromContext(ctx)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      icapService.Name + "-deployment",
			Namespace: icapService.Namespace,
			Labels: map[string]string{
				"app":     "icap",
				"service": icapService.Name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &icapService.Spec.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":     "icap",
					"service": icapService.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":     "icap",
						"service": icapService.Name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "c-icap",
							Image: "nginx:alpine",
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 1344,
									Name:          "icap",
								},
							},
						},
						{
							Name:  "clamav",
							Image: icapService.Spec.ClamAVConfig.Image,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 3310,
									Name:          "clamav",
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "CLAMAV_NO_FRESHCLAM",
									Value: "false",
								},
							},
						},
					},
				},
			},
		},
	}

	// Set ICAPService as owner of the Deployment
	if err := ctrl.SetControllerReference(icapService, deployment, r.Scheme); err != nil {
		return err
	}

	// Check if deployment exists
	found := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create deployment
		logger.Info("Creating Deployment", "name", deployment.Name)
		return r.Create(ctx, deployment)
	} else if err != nil {
		return err
	}

	// Update deployment if needed
	if *found.Spec.Replicas != icapService.Spec.Replicas {
		found.Spec.Replicas = &icapService.Spec.Replicas
		logger.Info("Updating Deployment replicas", "name", deployment.Name, "replicas", icapService.Spec.Replicas)
		return r.Update(ctx, found)
	}

	return nil
}

// reconcileService creates or updates the ICAP Service
func (r *ICAPServiceReconciler) reconcileService(ctx context.Context, icapService *securityv1alpha1.ICAPService) error {
	logger := log.FromContext(ctx)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      icapService.Name + "-service",
			Namespace: icapService.Namespace,
			Labels: map[string]string{
				"app":     "icap",
				"service": icapService.Name,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app":     "icap",
				"service": icapService.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "icap",
					Port:     1344,
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set ICAPService as owner
	if err := ctrl.SetControllerReference(icapService, service, r.Scheme); err != nil {
		return err
	}

	// Check if service exists
	found := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("Creating Service", "name", service.Name)
		return r.Create(ctx, service)
	} else if err != nil {
		return err
	}

	return nil
}

// updateStatus updates the ICAPService status
func (r *ICAPServiceReconciler) updateStatus(ctx context.Context, icapService *securityv1alpha1.ICAPService) error {
	logger := log.FromContext(ctx)

	// Get the deployment to check ready replicas
	deployment := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      icapService.Name + "-deployment",
		Namespace: icapService.Namespace,
	}, deployment)
	if err != nil {
		return err
	}

	// Calculate health score with BOTH deployment and icapService
	healthScore := r.calculateHealthScore(deployment, icapService) // ← FIXED: Added icapService parameter

	// Update status
	icapService.Status.ReadyReplicas = deployment.Status.ReadyReplicas
	icapService.Status.CurrentHealthScore = healthScore
	icapService.Status.LastScalingTime = time.Now().Format(time.RFC3339)

	// Add condition
	condition := securityv1alpha1.Condition{
		Type:               "Ready",
		Status:             "True",
		LastTransitionTime: time.Now().Format(time.RFC3339),
		Reason:             "DeploymentReady",
		Message:            fmt.Sprintf("%d/%d replicas ready", deployment.Status.ReadyReplicas, icapService.Spec.Replicas),
	}
	icapService.Status.Conditions = []securityv1alpha1.Condition{condition}

	logger.Info("Updating status", "readyReplicas", deployment.Status.ReadyReplicas, "healthScore", healthScore)
	return r.Status().Update(ctx, icapService)
}

// calculateHealthScore computes adaptive health score
func (r *ICAPServiceReconciler) calculateHealthScore(deployment *appsv1.Deployment, icapService *securityv1alpha1.ICAPService) int32 {
	// Use advanced adaptive health monitoring
	metrics := health.CalculateHealth(deployment, icapService)

	// Log health details for debugging
	logger := log.Log.WithName("health")
	logger.Info("Health metrics calculated",
		"readiness", fmt.Sprintf("%.1f", metrics.ReadinessScore),
		"latency", fmt.Sprintf("%.1f", metrics.LatencyScore),
		"signatures", fmt.Sprintf("%.1f", metrics.SignatureScore),
		"errors", fmt.Sprintf("%.1f", metrics.ErrorScore),
		"resources", fmt.Sprintf("%.1f", metrics.ResourceScore),
		"queue", fmt.Sprintf("%.1f", metrics.QueueScore),
		"overall", metrics.OverallScore,
		"context", fmt.Sprintf("%+v", metrics.Context),
	)

	return metrics.OverallScore
}

// SetupWithManager sets up the controller with the Manager.
func (r *ICAPServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ICAPService{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Named("icapservice").
		Complete(r)
}
