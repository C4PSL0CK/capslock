package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EnvironmentContext holds detected environment information.
type EnvironmentContext struct {
	Namespace              string
	EnvironmentType        Environment
	SecurityLevel          SecurityLevel
	RiskTolerance          string
	ComplianceRequirements []string
	Confidence             float64
	Labels                 map[string]string
	DetectedAt             time.Time
}

// PolicyScore represents how well a policy fits an environment.
type PolicyScore struct {
	EnvironmentFit float64
	ComplianceFit  float64
	RiskAlignment  float64
	TotalScore     float64
	Reasoning      string
}

// PolicyRanking holds a template and its score for ranking purposes.
type PolicyRanking struct {
	Template *PolicyTemplate
	Score    *PolicyScore
}

// PolicyManager manages a set of loaded policy templates.
type PolicyManager struct {
	templates map[string]*PolicyTemplate
}

// NewPolicyManager creates a new PolicyManager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{templates: make(map[string]*PolicyTemplate)}
}

// Count returns the number of loaded templates.
func (pm *PolicyManager) Count() int {
	return len(pm.templates)
}

// ListTemplates returns the names of all loaded templates.
func (pm *PolicyManager) ListTemplates() []string {
	names := make([]string, 0, len(pm.templates))
	for name := range pm.templates {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LoadTemplates loads all policy templates from the given directory.
func (pm *PolicyManager) LoadTemplates(dir string) error {
	pattern := filepath.Join(dir, "*.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob %s: %w", pattern, err)
	}

	// Also check .yml
	pattern2 := filepath.Join(dir, "*.yml")
	files2, err := filepath.Glob(pattern2)
	if err == nil {
		files = append(files, files2...)
	}

	if len(files) == 0 {
		return fmt.Errorf("no templates found in %s", dir)
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", f, err)
		}
		var t PolicyTemplate
		if err := yaml.Unmarshal(data, &t); err != nil {
			return fmt.Errorf("failed to parse %s: %w", f, err)
		}
		// Back-fill Environment from TargetEnvironment if not set
		if t.Environment == "" && t.TargetEnvironment != "" {
			t.Environment = Environment(t.TargetEnvironment)
		}
		pm.templates[t.Name] = &t
	}

	if len(pm.templates) == 0 {
		return fmt.Errorf("no valid templates loaded from %s", dir)
	}

	return nil
}

// GetAllTemplates returns all loaded templates.
func (pm *PolicyManager) GetAllTemplates() []*PolicyTemplate {
	out := make([]*PolicyTemplate, 0, len(pm.templates))
	for _, t := range pm.templates {
		out = append(out, t)
	}
	return out
}

// GetTemplate returns the template with the given name.
func (pm *PolicyManager) GetTemplate(name string) (*PolicyTemplate, error) {
	t, ok := pm.templates[name]
	if !ok {
		return nil, fmt.Errorf("template %q not found", name)
	}
	return t, nil
}

// GetTemplatesByEnvironment returns all templates for the given environment.
func (pm *PolicyManager) GetTemplatesByEnvironment(env Environment) []*PolicyTemplate {
	var out []*PolicyTemplate
	for _, t := range pm.templates {
		if t.Environment == env {
			out = append(out, t)
		}
	}
	return out
}

// ValidateTemplate validates a single policy template.
func (pm *PolicyManager) ValidateTemplate(t *PolicyTemplate) error {
	if t.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if t.Version == "" {
		return fmt.Errorf("template version is required")
	}

	// Validate environment
	switch t.Environment {
	case EnvironmentDev, EnvironmentStaging, EnvironmentProd:
		// valid
	default:
		return fmt.Errorf("invalid environment %q: must be dev, staging, or prod", t.Environment)
	}

	// Validate scanning mode if set
	switch t.IcapConfig.ScanningMode {
	case "", "block", "warn", "log-only":
		// valid
	default:
		return fmt.Errorf("invalid scanning mode %q: must be block, warn, or log-only", t.IcapConfig.ScanningMode)
	}

	// Validate max file size format if set
	if t.IcapConfig.MaxFileSize != "" {
		if err := validateFileSizeFormat(t.IcapConfig.MaxFileSize); err != nil {
			return fmt.Errorf("invalid max_file_size: %w", err)
		}
	}

	// Validate timeout — check both Timeout and ScanTimeoutSeconds
	timeout := t.PerformanceConfig.Timeout
	if timeout == 0 {
		timeout = t.PerformanceConfig.ScanTimeoutSeconds
	}
	if timeout < 0 {
		return fmt.Errorf("timeout must be non-negative, got %d", timeout)
	}

	// Validate compliance standards
	validStandards := map[string]bool{"cis": true, "pci-dss": true}
	for _, s := range t.ComplianceConfig.Standards {
		if !validStandards[s] {
			return fmt.Errorf("invalid compliance standard %q: must be cis or pci-dss", s)
		}
	}

	return nil
}

// ValidateAllTemplates validates all loaded templates.
func (pm *PolicyManager) ValidateAllTemplates() error {
	for name, t := range pm.templates {
		if err := pm.ValidateTemplate(t); err != nil {
			return fmt.Errorf("template %q is invalid: %w", name, err)
		}
	}
	return nil
}

// validateFileSizeFormat validates that a file size string matches the pattern
// e.g. "100MB", "50GB", "1TB", "500KB"
func validateFileSizeFormat(s string) error {
	re := regexp.MustCompile(`^\d+(KB|MB|GB|TB)$`)
	if !re.MatchString(s) {
		return fmt.Errorf("invalid file size format %q: expected format like 100MB", s)
	}
	return nil
}

// PolicySelector selects the best policy for a given environment context.
type PolicySelector struct {
	manager           *PolicyManager
	environmentWeight float64
	complianceWeight  float64
	riskWeight        float64
}

// NewPolicySelector creates a new PolicySelector with default weights.
func NewPolicySelector(pm *PolicyManager) *PolicySelector {
	return &PolicySelector{
		manager:           pm,
		environmentWeight: 0.4,
		complianceWeight:  0.3,
		riskWeight:        0.3,
	}
}

// NewPolicySelectorWithWeights creates a PolicySelector with custom weights.
// Returns an error if the weights don't sum to approximately 1.0.
func NewPolicySelectorWithWeights(pm *PolicyManager, envWeight, complianceWeight, riskWeight float64) (*PolicySelector, error) {
	sum := envWeight + complianceWeight + riskWeight
	if sum < 0.99 || sum > 1.01 {
		return nil, fmt.Errorf("weights must sum to 1.0, got %.2f", sum)
	}
	return &PolicySelector{
		manager:           pm,
		environmentWeight: envWeight,
		complianceWeight:  complianceWeight,
		riskWeight:        riskWeight,
	}, nil
}

// SelectPolicy selects the best-fit policy template for the given context.
func (ps *PolicySelector) SelectPolicy(ctx *EnvironmentContext) (*PolicyTemplate, *PolicyScore, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("environment context is required")
	}

	var best *PolicyTemplate
	var bestScore *PolicyScore

	for _, t := range ps.manager.templates {
		score := ps.calculateScore(t, ctx)
		if best == nil || score.TotalScore > bestScore.TotalScore {
			best = t
			bestScore = score
		}
	}

	if best == nil {
		return nil, nil, fmt.Errorf("no policy templates loaded")
	}

	return best, bestScore, nil
}

// SelectPolicyWithScores returns the best policy and all scored rankings.
func (ps *PolicySelector) SelectPolicyWithScores(ctx *EnvironmentContext) (*PolicyTemplate, []PolicyRanking, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("environment context is required")
	}

	var rankings []PolicyRanking
	for _, t := range ps.manager.templates {
		score := ps.calculateScore(t, ctx)
		rankings = append(rankings, PolicyRanking{Template: t, Score: score})
	}

	if len(rankings) == 0 {
		return nil, nil, fmt.Errorf("no policy templates loaded")
	}

	// Sort by total score descending
	sort.Slice(rankings, func(i, j int) bool {
		return rankings[i].Score.TotalScore > rankings[j].Score.TotalScore
	})

	return rankings[0].Template, rankings, nil
}

// calculateScore computes the weighted score of a template for the given context.
func (ps *PolicySelector) calculateScore(t *PolicyTemplate, ctx *EnvironmentContext) *PolicyScore {
	envFit := ps.calculateEnvironmentFit(ctx, t)
	compFit := ps.calculateComplianceFit(ctx, t)
	riskAlign := ps.calculateRiskAlignment(ctx, t)

	total := envFit*ps.environmentWeight + compFit*ps.complianceWeight + riskAlign*ps.riskWeight

	reasoning := fmt.Sprintf("env=%.2f comp=%.2f risk=%.2f total=%.2f", envFit, compFit, riskAlign, total)

	return &PolicyScore{
		EnvironmentFit: envFit,
		ComplianceFit:  compFit,
		RiskAlignment:  riskAlign,
		TotalScore:     total,
		Reasoning:      reasoning,
	}
}

// calculateEnvironmentFit returns how well a template's environment matches the context.
func (ps *PolicySelector) calculateEnvironmentFit(ctx *EnvironmentContext, t *PolicyTemplate) float64 {
	if ctx.EnvironmentType == t.Environment {
		return 1.0
	}
	// Partial credit for adjacent environments
	switch ctx.EnvironmentType {
	case EnvironmentDev:
		if t.Environment == EnvironmentStaging {
			return 0.6
		}
		return 0.3
	case EnvironmentStaging:
		if t.Environment == EnvironmentDev {
			return 0.5
		}
		if t.Environment == EnvironmentProd {
			return 0.3
		}
	case EnvironmentProd:
		return 0.3
	}
	return 0.3
}

// calculateComplianceFit returns the fraction of required compliance standards met.
func (ps *PolicySelector) calculateComplianceFit(ctx *EnvironmentContext, t *PolicyTemplate) float64 {
	if len(ctx.ComplianceRequirements) == 0 {
		return 1.0
	}

	met := 0
	for _, req := range ctx.ComplianceRequirements {
		for _, std := range t.ComplianceConfig.Standards {
			if std == req {
				met++
				break
			}
		}
	}

	return float64(met) / float64(len(ctx.ComplianceRequirements))
}

// calculateRiskAlignment returns how well the template's risk posture matches the context.
func (ps *PolicySelector) calculateRiskAlignment(ctx *EnvironmentContext, t *PolicyTemplate) float64 {
	mode := t.IcapConfig.ScanningMode
	risk := strings.ToLower(ctx.RiskTolerance)

	switch risk {
	case "high": // high risk tolerance -> prefer log-only
		if mode == "log-only" {
			return 1.0
		}
		if mode == "warn" {
			return 0.5
		}
		return 0.0 // block mode is wrong for high-risk-tolerance env
	case "medium": // medium risk tolerance -> prefer warn
		if mode == "warn" {
			return 1.0
		}
		if mode == "log-only" {
			return 0.5
		}
		return 0.3
	case "low": // low risk tolerance -> prefer block
		if mode == "block" {
			return 1.0
		}
		if mode == "warn" {
			return 0.5
		}
		return 0.2
	}

	return 0.5
}

// score is the old simple scoring method kept for backward compatibility.
func (ps *PolicySelector) score(t *PolicyTemplate, ctx *EnvironmentContext) float64 {
	return ps.calculateScore(t, ctx).TotalScore
}
