package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/conflict"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// Server represents the API server
type Server struct {
	detector       *detector.EnvironmentDetector
	policyManager  *policy.PolicyManager
	policySelector *policy.PolicySelector
	conflictDetector *conflict.ConflictDetector
	version        string
}

// NewServer creates a new API server
func NewServer() (*Server, error) {
	// Initialize detector
	det, err := detector.NewEnvironmentDetector()
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}

	// Initialize policy manager
	pm := policy.NewPolicyManager()
	if err := pm.LoadTemplates("policies/templates"); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Initialize policy selector
	ps := policy.NewPolicySelector(pm)

	// Initialize conflict detector
	cd := conflict.NewConflictDetector()

	return &Server{
		detector:         det,
		policyManager:    pm,
		policySelector:   ps,
		conflictDetector: cd,
		version:          "1.0.0",
	}, nil
}

// HandleDetect handles environment detection requests
func (s *Server) HandleDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DetectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Namespace == "" {
		s.sendError(w, "Namespace is required", http.StatusBadRequest)
		return
	}

	// Detect environment
	ctx := context.Background()
	envCtx, err := s.detector.Detect(ctx, req.Namespace)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Detection failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert to response
	resp := DetectResponse{
		Namespace:              envCtx.Namespace,
		EnvironmentType:        string(envCtx.EnvironmentType),
		SecurityLevel:          string(envCtx.SecurityLevel),
		RiskTolerance:          envCtx.RiskTolerance,
		ComplianceRequirements: envCtx.ComplianceRequirements,
		Confidence:             envCtx.Confidence,
		Labels:                 envCtx.Labels,
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// HandleListPolicies handles listing all policies
func (s *Server) HandleListPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	templates := s.policyManager.GetAllTemplates()
	summaries := make([]PolicySummary, len(templates))

	for i, t := range templates {
		summaries[i] = PolicySummary{
			Name:        t.Name,
			Version:     t.Version,
			Environment: string(t.Environment),
			Description: t.Description,
			Compliance:  t.Compliance.Standards,
		}
	}

	resp := ListPoliciesResponse{
		Policies: summaries,
		Total:    len(summaries),
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// HandleGetPolicy handles getting a specific policy
func (s *Server) HandleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyName := r.URL.Query().Get("name")
	if policyName == "" {
		s.sendError(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	template, err := s.policyManager.GetTemplate(policyName)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Policy not found: %v", err), http.StatusNotFound)
		return
	}

	resp := GetPolicyResponse{
		Policy: template,
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// HandleSelectPolicy handles policy selection requests
func (s *Server) HandleSelectPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SelectPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Namespace == "" {
		s.sendError(w, "Namespace is required", http.StatusBadRequest)
		return
	}

	// First detect environment
	ctx := context.Background()
	envCtx, err := s.detector.Detect(ctx, req.Namespace)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Detection failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Select best policy
	selectedPolicy, score, err := s.policySelector.SelectPolicy(envCtx)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Policy selection failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Build response
	resp := SelectPolicyResponse{
		SelectedPolicy: selectedPolicy,
		EnvironmentFit: score.EnvironmentFit,
		ComplianceFit:  score.ComplianceFit,
		RiskAlignment:  score.RiskAlignment,
		TotalScore:     score.TotalScore,
		Reasoning:      score.Reasoning,
		DetectionContext: &DetectResponse{
			Namespace:              envCtx.Namespace,
			EnvironmentType:        string(envCtx.EnvironmentType),
			SecurityLevel:          string(envCtx.SecurityLevel),
			RiskTolerance:          envCtx.RiskTolerance,
			ComplianceRequirements: envCtx.ComplianceRequirements,
			Confidence:             envCtx.Confidence,
			Labels:                 envCtx.Labels,
		},
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// HandleDetectConflicts handles conflict detection requests
func (s *Server) HandleDetectConflicts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DetectConflictsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.PolicyNames) < 2 {
		s.sendError(w, "At least 2 policies required for conflict detection", http.StatusBadRequest)
		return
	}

	// Get policies
	policies := make([]*policy.PolicyTemplate, 0, len(req.PolicyNames))
	for _, name := range req.PolicyNames {
		p, err := s.policyManager.GetTemplate(name)
		if err != nil {
			s.sendError(w, fmt.Sprintf("Policy not found: %s", name), http.StatusNotFound)
			return
		}
		policies = append(policies, p)
	}

	// Detect conflicts
	report, err := s.conflictDetector.DetectConflicts(policies)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Conflict detection failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Build response
	summaries := make([]ConflictSummary, len(report.Conflicts))
	for i, c := range report.Conflicts {
		policyNames := make([]string, len(c.Policies))
		for j, p := range c.Policies {
			policyNames[j] = p.Name
		}
		summaries[i] = ConflictSummary{
			ID:          c.ID,
			Type:        string(c.Type),
			Severity:    string(c.Severity),
			Description: c.Description,
			PolicyNames: policyNames,
		}
	}

	resp := DetectConflictsResponse{
		TotalConflicts: report.TotalConflicts,
		Conflicts:      summaries,
		GeneratedAt:    report.GeneratedAt,
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// HandleResolveConflicts handles conflict resolution requests
func (s *Server) HandleResolveConflicts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ResolveConflictsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get policies
	policies := make([]*policy.PolicyTemplate, 0, len(req.PolicyNames))
	for _, name := range req.PolicyNames {
		p, err := s.policyManager.GetTemplate(name)
		if err != nil {
			s.sendError(w, fmt.Sprintf("Policy not found: %s", name), http.StatusNotFound)
			return
		}
		policies = append(policies, p)
	}

	// Detect conflicts first
	conflictReport, err := s.conflictDetector.DetectConflicts(policies)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Conflict detection failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse strategy
	var strategy conflict.ResolutionStrategy
	switch req.Strategy {
	case "precedence":
		strategy = conflict.StrategyPrecedence
	case "security-first":
		strategy = conflict.StrategySecurityFirst
	case "environment-aware":
		strategy = conflict.StrategyEnvironmentAware
	case "manual":
		strategy = conflict.StrategyManual
	default:
		strategy = conflict.StrategyPrecedence
	}

	// Create resolver
	resolver := conflict.NewConflictResolver(strategy)

	// Get environment context if needed
	var envCtx *policy.EnvironmentContext
	if req.Namespace != "" && strategy == conflict.StrategyEnvironmentAware {
		ctx := context.Background()
		envCtx, err = s.detector.Detect(ctx, req.Namespace)
		if err != nil {
			s.sendError(w, fmt.Sprintf("Detection failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Resolve conflicts
	resolutionReport, err := resolver.ResolveConflicts(conflictReport, envCtx)
	if err != nil {
		s.sendError(w, fmt.Sprintf("Conflict resolution failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Build response
	summaries := make([]ResolutionSummary, len(resolutionReport.Resolutions))
	for i, r := range resolutionReport.Resolutions {
		chosenName := ""
		if r.ChosenPolicy != nil {
			chosenName = r.ChosenPolicy.Name
		}
		summaries[i] = ResolutionSummary{
			ConflictID:    r.ConflictID,
			Strategy:      string(r.Strategy),
			ChosenPolicy:  chosenName,
			RejectedCount: len(r.RejectedPolicies),
			Reason:        r.Reason,
		}
	}

	resp := ResolveConflictsResponse{
		TotalResolved: resolutionReport.TotalResolved,
		Resolutions:   summaries,
		FinalPolicy:   resolutionReport.FinalPolicy,
		GeneratedAt:   resolutionReport.GeneratedAt,
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// HandleHealth handles health check requests
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	err := s.detector.HealthCheck(ctx)

	resp := HealthResponse{
		Status:              "healthy",
		Version:             s.version,
		Timestamp:           time.Now(),
		KubernetesConnected: err == nil,
	}

	if err != nil {
		resp.Status = "degraded"
	}

	s.sendJSON(w, resp, http.StatusOK)
}

// Helper methods

func (s *Server) sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) sendError(w http.ResponseWriter, message string, code int) {
	resp := ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	}
	s.sendJSON(w, resp, code)
}