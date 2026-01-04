package engine

import (
	"context"
	"fmt"
	"log"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/conflict"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/mocks"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// PolicyEngine orchestrates the complete policy application workflow
type PolicyEngine struct {
	detector         *detector.EnvironmentDetector
	policyManager    *policy.PolicyManager
	policySelector   *policy.PolicySelector
	conflictDetector *conflict.ConflictDetector
	conflictResolver *conflict.ConflictResolver
	icapOperator     *mocks.MockIcapOperator
	serviceDiscovery *mocks.MockServiceDiscovery
	deploymentSystem *mocks.MockDeploymentSystem
}

// NewPolicyEngine creates a new policy engine with all dependencies
func NewPolicyEngine() (*PolicyEngine, error) {
	// Initialize detector
	det, err := detector.NewEnvironmentDetector()
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}

	// Initialize policy manager
	pm := policy.NewPolicyManager()
	if err := pm.LoadTemplates("../../policies/templates"); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Initialize policy selector
	ps := policy.NewPolicySelector(pm)

	// Initialize conflict components
	cd := conflict.NewConflictDetector()
	cr := conflict.NewConflictResolver(conflict.StrategyEnvironmentAware)

	// Initialize mock components
	icapOp := mocks.NewMockIcapOperator()
	svcDiscovery := mocks.NewMockServiceDiscovery()
	deploySystem := mocks.NewMockDeploymentSystem()

	return &PolicyEngine{
		detector:         det,
		policyManager:    pm,
		policySelector:   ps,
		conflictDetector: cd,
		conflictResolver: cr,
		icapOperator:     icapOp,
		serviceDiscovery: svcDiscovery,
		deploymentSystem: deploySystem,
	}, nil
}

// ApplyPolicyToNamespace executes the complete workflow to apply a policy to a namespace
func (pe *PolicyEngine) ApplyPolicyToNamespace(ctx context.Context, namespace string) (*ApplyResult, error) {
	result := &ApplyResult{
		Namespace: namespace,
		Steps:     []string{},
	}

	log.Printf("🚀 Starting policy application workflow for namespace: %s", namespace)
	result.Steps = append(result.Steps, fmt.Sprintf("Started workflow for namespace: %s", namespace))

	// Step 1: Detect environment
	log.Println("📊 Step 1: Detecting environment...")
	result.Steps = append(result.Steps, "Step 1: Environment detection")

	envCtx, err := pe.detector.Detect(ctx, namespace)
	if err != nil {
		result.Error = fmt.Sprintf("Environment detection failed: %v", err)
		pe.deploymentSystem.MarkPolicyFailed(namespace, "unknown", result.Error)
		return result, fmt.Errorf("detection failed: %w", err)
	}

	log.Printf("✅ Detected environment: %s (confidence: %.2f)", envCtx.EnvironmentType, envCtx.Confidence)
	result.DetectedEnvironment = string(envCtx.EnvironmentType)
	result.Confidence = envCtx.Confidence
	result.Steps = append(result.Steps, fmt.Sprintf("Detected: %s (confidence: %.2f)", envCtx.EnvironmentType, envCtx.Confidence))

	// Step 2: Select best policy
	log.Println("🎯 Step 2: Selecting optimal policy...")
	result.Steps = append(result.Steps, "Step 2: Policy selection")

	selectedPolicy, score, err := pe.policySelector.SelectPolicy(envCtx)
	if err != nil {
		result.Error = fmt.Sprintf("Policy selection failed: %v", err)
		pe.deploymentSystem.MarkPolicyFailed(namespace, "unknown", result.Error)
		return result, fmt.Errorf("selection failed: %w", err)
	}

	log.Printf("✅ Selected policy: %s (score: %.2f)", selectedPolicy.Name, score.TotalScore)
	result.SelectedPolicy = selectedPolicy.Name
	result.SelectionScore = score.TotalScore
	result.Steps = append(result.Steps, fmt.Sprintf("Selected: %s (score: %.2f)", selectedPolicy.Name, score.TotalScore))

	// Step 3: Check for conflicts (with other policies that might apply)
	log.Println("🔍 Step 3: Checking for conflicts...")
	result.Steps = append(result.Steps, "Step 3: Conflict detection")

	// Get all templates for this environment type
	candidatePolicies := pe.policyManager.GetTemplatesByEnvironment(envCtx.EnvironmentType)
	
	if len(candidatePolicies) > 1 {
		conflictReport, err := pe.conflictDetector.DetectConflicts(candidatePolicies)
		if err != nil {
			log.Printf("⚠️  Conflict detection error: %v", err)
		} else if conflictReport.TotalConflicts > 0 {
			log.Printf("⚠️  Found %d conflicts, resolving...", conflictReport.TotalConflicts)
			result.ConflictsDetected = conflictReport.TotalConflicts
			result.Steps = append(result.Steps, fmt.Sprintf("Detected %d conflicts", conflictReport.TotalConflicts))

			// Step 4: Resolve conflicts
			log.Println("🔧 Step 4: Resolving conflicts...")
			result.Steps = append(result.Steps, "Step 4: Conflict resolution")

			resolutionReport, err := pe.conflictResolver.ResolveConflicts(conflictReport, envCtx)
			if err != nil {
				result.Error = fmt.Sprintf("Conflict resolution failed: %v", err)
				pe.deploymentSystem.MarkPolicyFailed(namespace, selectedPolicy.Name, result.Error)
				return result, fmt.Errorf("resolution failed: %w", err)
			}

			if resolutionReport.FinalPolicy != nil {
				selectedPolicy = resolutionReport.FinalPolicy
				log.Printf("✅ Conflicts resolved, final policy: %s", selectedPolicy.Name)
				result.SelectedPolicy = selectedPolicy.Name
				result.ConflictsResolved = resolutionReport.TotalResolved
				result.Steps = append(result.Steps, fmt.Sprintf("Resolved %d conflicts", resolutionReport.TotalResolved))
			}
		} else {
			log.Println("✅ No conflicts detected")
			result.Steps = append(result.Steps, "No conflicts detected")
		}
	} else {
		log.Println("✅ Single policy candidate, no conflicts possible")
		result.Steps = append(result.Steps, "Single policy candidate, no conflicts")
	}

	// Step 5: Apply policy via ICAP operator
	log.Println("📦 Step 5: Applying policy to namespace...")
	result.Steps = append(result.Steps, "Step 5: Policy application")

	err = pe.icapOperator.ApplyPolicy(namespace, selectedPolicy)
	if err != nil {
		result.Error = fmt.Sprintf("Policy application failed: %v", err)
		pe.deploymentSystem.MarkPolicyFailed(namespace, selectedPolicy.Name, result.Error)
		return result, fmt.Errorf("application failed: %w", err)
	}

	log.Printf("✅ Policy applied successfully")
	result.Steps = append(result.Steps, "Policy applied successfully")

	// Step 6: Report status to deployment system
	log.Println("📝 Step 6: Reporting deployment status...")
	result.Steps = append(result.Steps, "Step 6: Status reporting")

	err = pe.deploymentSystem.ReportPolicyStatus(namespace, selectedPolicy.Name, "deployed")
	if err != nil {
		log.Printf("⚠️  Status reporting failed: %v", err)
	} else {
		log.Println("✅ Status reported to deployment system")
		result.Steps = append(result.Steps, "Status reported")
	}

	// Step 7: Verify with service discovery
	log.Println("🔍 Step 7: Verifying services...")
	result.Steps = append(result.Steps, "Step 7: Service verification")

	services, err := pe.serviceDiscovery.GetHealthyServices(string(envCtx.EnvironmentType))
	if err != nil {
		log.Printf("⚠️  Service discovery failed: %v", err)
	} else {
		log.Printf("✅ Found %d healthy services in environment", len(services))
		result.HealthyServices = len(services)
		result.Steps = append(result.Steps, fmt.Sprintf("Verified %d healthy services", len(services)))
	}

	result.Success = true
	log.Printf("🎉 Workflow completed successfully for namespace: %s", namespace)
	result.Steps = append(result.Steps, "✅ Workflow completed successfully")

	return result, nil
}

// GetPolicyStatus retrieves the current policy status for a namespace
func (pe *PolicyEngine) GetPolicyStatus(namespace string) (*mocks.PolicyStatus, error) {
	return pe.deploymentSystem.GetPolicyStatus(namespace)
}

// ListAppliedPolicies returns all policies currently applied across namespaces
func (pe *PolicyEngine) ListAppliedPolicies() []*mocks.AppliedPolicy {
	return pe.icapOperator.ListAppliedPolicies()
}

// RemovePolicy removes a policy from a namespace
func (pe *PolicyEngine) RemovePolicy(namespace string) error {
	log.Printf("🗑️  Removing policy from namespace: %s", namespace)
	
	// Remove from ICAP operator
	err := pe.icapOperator.RemovePolicy(namespace)
	if err != nil {
		return fmt.Errorf("failed to remove policy: %w", err)
	}

	// Note: We don't remove from deployment system as it maintains history
	// The deployment system tracks all deployments for audit purposes

	log.Println("✅ Policy removed successfully")
	return nil
}

// ApplyResult contains the result of a policy application workflow
type ApplyResult struct {
	Namespace           string
	DetectedEnvironment string
	Confidence          float64
	SelectedPolicy      string
	SelectionScore      float64
	ConflictsDetected   int
	ConflictsResolved   int
	HealthyServices     int
	Success             bool
	Error               string
	Steps               []string
}