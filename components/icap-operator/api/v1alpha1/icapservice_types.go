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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ICAPServiceSpec defines the desired state of ICAPService
type ICAPServiceSpec struct {
	// Replicas is the desired number of ICAP service replicas
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	Replicas int32 `json:"replicas,omitempty"`

	// ClamAV configuration
	ClamAVConfig ClamAVConfig `json:"clamavConfig,omitempty"`

	// Health check thresholds
	HealthThresholds HealthThresholds `json:"healthThresholds,omitempty"`

	// Scaling policy
	ScalingPolicy ScalingPolicy `json:"scalingPolicy,omitempty"`
}

// ClamAVConfig defines ClamAV-specific configuration
type ClamAVConfig struct {
	// SignatureUpdateInterval defines how often to update virus signatures
	// +kubebuilder:default="1h"
	SignatureUpdateInterval string `json:"signatureUpdateInterval,omitempty"`

	// Image is the ClamAV container image
	// +kubebuilder:default="clamav/clamav:latest"
	Image string `json:"image,omitempty"`
}

// HealthThresholds defines acceptable health metric thresholds
type HealthThresholds struct {
	// MaxLatency is the maximum acceptable scan latency
	// +kubebuilder:default="500ms"
	MaxLatency string `json:"maxLatency,omitempty"`

	// MaxErrorRate is the maximum acceptable error rate (0.0 to 1.0)
	// +kubebuilder:default="0.05"
	MaxErrorRate string `json:"maxErrorRate,omitempty"`

	// MaxSignatureAge is the maximum age of virus signatures
	// +kubebuilder:default="24h"
	MaxSignatureAge string `json:"maxSignatureAge,omitempty"`
}

// ScalingPolicy defines autoscaling behavior
type ScalingPolicy struct {
	// MinReplicas is the minimum number of replicas
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	MinReplicas int32 `json:"minReplicas,omitempty"`

	// MaxReplicas is the maximum number of replicas
	// +kubebuilder:default=10
	// +kubebuilder:validation:Maximum=50
	MaxReplicas int32 `json:"maxReplicas,omitempty"`

	// TargetHealthScore is the desired health score (0-100)
	// +kubebuilder:default=80
	// +kubebuilder:validation:Minimum=50
	// +kubebuilder:validation:Maximum=100
	TargetHealthScore int32 `json:"targetHealthScore,omitempty"`
}

// ICAPServiceStatus defines the observed state of ICAPService
type ICAPServiceStatus struct {
	// ReadyReplicas is the number of ready ICAP pods
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// CurrentHealthScore is the current health score (0-100)
	CurrentHealthScore int32 `json:"currentHealthScore,omitempty"`

	// LastScalingTime is when the last scaling event occurred
	LastScalingTime string `json:"lastScalingTime,omitempty"`

	// Conditions represent the latest available observations
	Conditions []Condition `json:"conditions,omitempty"`
}

// Condition describes the state of the ICAP service
type Condition struct {
	// Type of condition
	Type string `json:"type"`

	// Status of the condition (True, False, Unknown)
	Status string `json:"status"`

	// LastTransitionTime is the last time the condition transitioned
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine-readable explanation
	Reason string `json:"reason,omitempty"`

	// Message is a human-readable explanation
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ICAPService is the Schema for the icapservices API
type ICAPService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ICAPServiceSpec   `json:"spec,omitempty"`
	Status ICAPServiceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ICAPServiceList contains a list of ICAPService
type ICAPServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ICAPService `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ICAPService{}, &ICAPServiceList{})
}
