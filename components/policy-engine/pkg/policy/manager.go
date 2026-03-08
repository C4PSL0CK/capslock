package policy

import (
	"fmt"
	"time"
)

// EnvironmentContext holds detected environment information.
type EnvironmentContext struct {
	Namespace              string
	EnvironmentType        Environment
	SecurityLevel          string
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

// PolicyManager manages a set of loaded policy templates.
type PolicyManager struct {
	templates map[string]*PolicyTemplate
}

// NewPolicyManager creates a new PolicyManager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{templates: make(map[string]*PolicyTemplate)}
}

// LoadTemplates loads all policy templates from the given directory.
func (pm *PolicyManager) LoadTemplates(dir string) error {
	templates, err := LoadPolicyTemplates()
	if err != nil {
		return err
	}
	for _, t := range templates {
		pm.templates[t.Name] = t
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

// PolicySelector selects the best policy for a given environment context.
type PolicySelector struct {
	manager *PolicyManager
}

// NewPolicySelector creates a new PolicySelector.
func NewPolicySelector(pm *PolicyManager) *PolicySelector {
	return &PolicySelector{manager: pm}
}

// SelectPolicy selects the best-fit policy template for the given context.
func (ps *PolicySelector) SelectPolicy(ctx *EnvironmentContext) (*PolicyTemplate, *PolicyScore, error) {
	var best *PolicyTemplate
	var bestScore float64

	for _, t := range ps.manager.templates {
		score := ps.score(t, ctx)
		if best == nil || score > bestScore {
			best = t
			bestScore = score
		}
	}

	if best == nil {
		return nil, nil, fmt.Errorf("no policy templates loaded")
	}

	return best, &PolicyScore{
		EnvironmentFit: bestScore,
		ComplianceFit:  bestScore,
		RiskAlignment:  bestScore,
		TotalScore:     bestScore,
		Reasoning:      "best available match",
	}, nil
}

func (ps *PolicySelector) score(t *PolicyTemplate, ctx *EnvironmentContext) float64 {
	if string(t.Environment) == string(ctx.EnvironmentType) {
		return 1.0
	}
	return 0.5
}
