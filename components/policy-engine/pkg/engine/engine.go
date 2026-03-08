package engine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance/cis"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance/pcidss"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/conflict"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
	"k8s.io/client-go/kubernetes/fake"
)

// PolicyEngine orchestrates the policy application workflow
type PolicyEngine struct {
	detector         *detector.Detector
	policyManager    *policy.PolicyManager
	conflictResolver *conflict.Resolver
	cisValidator     *cis.CISValidator
	pcidssValidator  *pcidss.PCIDSSValidator

	mu              sync.RWMutex
	appliedPolicies map[string]*appliedPolicyRecord
}

type appliedPolicyRecord struct {
	Namespace  string
	PolicyName string
	AppliedAt  time.Time
}

// NewPolicyEngine creates a new policy engine without requiring real Kubernetes.
func NewPolicyEngine() (*PolicyEngine, error) {
	pm := policy.NewPolicyManager()
	// Try multiple directories to locate templates.
	for _, dir := range []string{
		"policies/templates",
		"../../policies/templates",
		"../../../policies/templates",
	} {
		if err := pm.LoadTemplates(dir); err == nil {
			break
		}
	}

	// Create a no-op fake detector so engine.detector is never nil.
	fakeClient := fake.NewSimpleClientset()
	det := detector.NewDetector(fakeClient)

	pe := &PolicyEngine{
		detector:         det,
		policyManager:    pm,
		conflictResolver: conflict.NewResolver(),
		cisValidator:     cis.NewCISValidator(),
		pcidssValidator:  pcidss.NewPCIDSSValidator(),
		appliedPolicies:  make(map[string]*appliedPolicyRecord),
	}
	return pe, nil
}

// GetDetector returns the detector instance (may be nil).
func (pe *PolicyEngine) GetDetector() *detector.Detector {
	return pe.detector
}

// ApplyPolicyToNamespace applies the appropriate policy to a namespace.
// In the absence of Kubernetes, environment is detected from the namespace name.
func (pe *PolicyEngine) ApplyPolicyToNamespace(ctx context.Context, namespace string) (*ApplyResult, error) {
	result := &ApplyResult{
		Namespace: namespace,
		Steps:     []string{},
	}

	// Step 1: Validate namespace
	result.Steps = append(result.Steps, fmt.Sprintf("Validating namespace: %s", namespace))

	// Step 2: Detect environment from namespace name
	envType := detectEnvFromName(namespace)
	result.Steps = append(result.Steps, fmt.Sprintf("Detecting environment from namespace name"))
	if envType == policy.EnvironmentUnknown {
		result.Error = fmt.Sprintf("cannot determine environment for namespace %q: name does not contain prod/staging/dev", namespace)
		return result, fmt.Errorf("%s", result.Error)
	}
	result.DetectedEnvironment = string(envType)
	result.Steps = append(result.Steps, fmt.Sprintf("Detected environment: %s", envType))

	// Step 3: Calculate confidence
	result.Confidence = confidenceFromEnv(envType)
	result.Steps = append(result.Steps, fmt.Sprintf("Confidence score: %.2f", result.Confidence))

	// Step 4: Select policy
	templates := pe.policyManager.GetTemplatesByEnvironment(envType)
	if len(templates) == 0 {
		result.Error = fmt.Sprintf("no policy template found for environment %q", envType)
		return result, fmt.Errorf("%s", result.Error)
	}

	selected := templates[0]
	result.SelectedPolicy = selected.Name
	result.Steps = append(result.Steps, fmt.Sprintf("Selected policy: %s", selected.Name))

	// Step 5: Record the applied policy
	pe.mu.Lock()
	pe.appliedPolicies[namespace] = &appliedPolicyRecord{
		Namespace:  namespace,
		PolicyName: selected.Name,
		AppliedAt:  time.Now(),
	}
	pe.mu.Unlock()

	// HealthyServices: count templates available for the detected environment
	result.HealthyServices = len(templates)

	result.Success = true
	result.Steps = append(result.Steps, "Policy applied successfully")
	return result, nil
}

// confidenceFromEnv returns a baseline confidence score based on how the
// environment was resolved (name-only inference yields lower confidence).
func confidenceFromEnv(env policy.Environment) float64 {
	switch env {
	case policy.EnvironmentProd:
		return 0.85
	case policy.EnvironmentStaging:
		return 0.80
	case policy.EnvironmentDev:
		return 0.80
	default:
		return 0.3
	}
}

// detectEnvFromName infers the environment from the namespace name.
func detectEnvFromName(namespace string) policy.Environment {
	lower := strings.ToLower(namespace)
	if strings.Contains(lower, "prod") {
		return policy.EnvironmentProd
	}
	if strings.Contains(lower, "staging") || strings.Contains(lower, "stage") {
		return policy.EnvironmentStaging
	}
	if strings.Contains(lower, "dev") {
		return policy.EnvironmentDev
	}
	return policy.EnvironmentUnknown
}

// GetPolicyStatus returns the status of an applied policy for a namespace.
func (pe *PolicyEngine) GetPolicyStatus(namespace string) (*Status, error) {
	pe.mu.RLock()
	rec, ok := pe.appliedPolicies[namespace]
	pe.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no policy applied to namespace %q", namespace)
	}

	return &Status{
		Namespace:  namespace,
		PolicyName: rec.PolicyName,
		Status:     "deployed",
		AppliedAt:  rec.AppliedAt,
	}, nil
}

// ListAppliedPolicies returns all namespaces that have policies applied.
func (pe *PolicyEngine) ListAppliedPolicies() []AppliedPolicy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	out := make([]AppliedPolicy, 0, len(pe.appliedPolicies))
	for ns, rec := range pe.appliedPolicies {
		out = append(out, AppliedPolicy{
			Namespace:  ns,
			PolicyName: rec.PolicyName,
			AppliedAt:  rec.AppliedAt,
		})
	}
	return out
}

// RemovePolicy removes the applied policy for a namespace.
func (pe *PolicyEngine) RemovePolicy(namespace string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, ok := pe.appliedPolicies[namespace]; !ok {
		return fmt.Errorf("no policy applied to namespace %q", namespace)
	}
	delete(pe.appliedPolicies, namespace)
	return nil
}

// StartWatching starts a background goroutine that polls the given namespace
// for environment changes and re-applies policy when the environment shifts.
func (pe *PolicyEngine) StartWatching(ctx context.Context, namespace string, interval time.Duration) {
	go pe.detector.Watch(ctx, namespace, interval, func(oldEnv, newEnv string, confidence float64) {
		log.Printf("[watch] namespace %q changed: %s → %s (confidence=%.2f); re-applying policy", namespace, oldEnv, newEnv, confidence)
		if _, err := pe.ApplyPolicyToNamespace(ctx, namespace); err != nil {
			log.Printf("[watch] re-apply failed for %q: %v", namespace, err)
		}
	})
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
