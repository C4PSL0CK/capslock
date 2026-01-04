package api

import (
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// DetectRequest represents an environment detection request
type DetectRequest struct {
	Namespace string `json:"namespace"`
}

// DetectResponse represents an environment detection response
type DetectResponse struct {
	Namespace              string            `json:"namespace"`
	EnvironmentType        string            `json:"environmentType"`
	SecurityLevel          string            `json:"securityLevel"`
	RiskTolerance          string            `json:"riskTolerance"`
	ComplianceRequirements []string          `json:"complianceRequirements"`
	Confidence             float64           `json:"confidence"`
	Labels                 map[string]string `json:"labels"`
}

// ListPoliciesResponse represents the response for listing policies
type ListPoliciesResponse struct {
	Policies []PolicySummary `json:"policies"`
	Total    int             `json:"total"`
}

// PolicySummary provides a summary of a policy
type PolicySummary struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Environment string   `json:"environment"`
	Description string   `json:"description"`
	Compliance  []string `json:"compliance"`
}

// GetPolicyResponse represents the response for getting a policy
type GetPolicyResponse struct {
	Policy *policy.PolicyTemplate `json:"policy"`
}

// SelectPolicyRequest represents a policy selection request
type SelectPolicyRequest struct {
	Namespace string `json:"namespace"`
}

// SelectPolicyResponse represents a policy selection response
type SelectPolicyResponse struct {
	SelectedPolicy   *policy.PolicyTemplate `json:"selectedPolicy"`
	EnvironmentFit   float64                `json:"environmentFit"`
	ComplianceFit    float64                `json:"complianceFit"`
	RiskAlignment    float64                `json:"riskAlignment"`
	TotalScore       float64                `json:"totalScore"`
	Reasoning        string                 `json:"reasoning"`
	DetectionContext *DetectResponse        `json:"detectionContext"`
}

// DetectConflictsRequest represents a conflict detection request
type DetectConflictsRequest struct {
	PolicyNames []string `json:"policyNames"`
}

// DetectConflictsResponse represents a conflict detection response
type DetectConflictsResponse struct {
	TotalConflicts int               `json:"totalConflicts"`
	Conflicts      []ConflictSummary `json:"conflicts"`
	GeneratedAt    time.Time         `json:"generatedAt"`
}

// ConflictSummary provides a summary of a conflict
type ConflictSummary struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	PolicyNames []string `json:"policyNames"`
}

// ResolveConflictsRequest represents a conflict resolution request
type ResolveConflictsRequest struct {
	PolicyNames []string `json:"policyNames"`
	Strategy    string   `json:"strategy"`
	Namespace   string   `json:"namespace,omitempty"`
}

// ResolveConflictsResponse represents a conflict resolution response
type ResolveConflictsResponse struct {
	TotalResolved int                    `json:"totalResolved"`
	Resolutions   []ResolutionSummary    `json:"resolutions"`
	FinalPolicy   *policy.PolicyTemplate `json:"finalPolicy"`
	GeneratedAt   time.Time              `json:"generatedAt"`
}

// ResolutionSummary provides a summary of a conflict resolution
type ResolutionSummary struct {
	ConflictID    string `json:"conflictId"`
	Strategy      string `json:"strategy"`
	ChosenPolicy  string `json:"chosenPolicy"`
	RejectedCount int    `json:"rejectedCount"`
	Reason        string `json:"reason"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status              string    `json:"status"`
	Version             string    `json:"version"`
	Timestamp           time.Time `json:"timestamp"`
	KubernetesConnected bool      `json:"kubernetesConnected"`
}