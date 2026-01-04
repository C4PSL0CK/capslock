package mocks

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// EnvironmentMetadata represents metadata about a deployment environment
type EnvironmentMetadata struct {
	Name              string
	ClusterID         string
	Region            string
	ComplianceLevel   []string
	RiskTolerance     string
	MaxConcurrentDeps int
	AutoScaling       bool
	MonitoringEnabled bool
	LastUpdated       time.Time
}

// PolicyStatus represents the status of a policy in the deployment system
type PolicyStatus struct {
	Namespace      string
	PolicyName     string
	Status         string // "deployed", "deploying", "failed", "pending"
	DeployedAt     time.Time
	LastChecked    time.Time
	HealthStatus   string // "healthy", "degraded", "unhealthy"
	ErrorMessage   string
}

// MockDeploymentSystem simulates the Multi-Environment Deployment System (Component 4)
type MockDeploymentSystem struct {
	mu           sync.RWMutex
	environments map[string]*EnvironmentMetadata
	policyStatus map[string]*PolicyStatus // key: namespace
	callLog      []string
}

// NewMockDeploymentSystem creates a new mock deployment system
func NewMockDeploymentSystem() *MockDeploymentSystem {
	mock := &MockDeploymentSystem{
		environments: make(map[string]*EnvironmentMetadata),
		policyStatus: make(map[string]*PolicyStatus),
		callLog:      []string{},
	}

	// Initialize default environments
	mock.initializeDefaultEnvironments()
	return mock
}

// initializeDefaultEnvironments sets up realistic environment metadata
func (m *MockDeploymentSystem) initializeDefaultEnvironments() {
	m.environments["dev"] = &EnvironmentMetadata{
		Name:              "development",
		ClusterID:         "cluster-dev-001",
		Region:            "us-west-2",
		ComplianceLevel:   []string{},
		RiskTolerance:     "high",
		MaxConcurrentDeps: 50,
		AutoScaling:       true,
		MonitoringEnabled: true,
		LastUpdated:       time.Now(),
	}

	m.environments["staging"] = &EnvironmentMetadata{
		Name:              "staging",
		ClusterID:         "cluster-staging-001",
		Region:            "us-west-2",
		ComplianceLevel:   []string{"soc2"},
		RiskTolerance:     "medium",
		MaxConcurrentDeps: 30,
		AutoScaling:       true,
		MonitoringEnabled: true,
		LastUpdated:       time.Now(),
	}

	m.environments["prod"] = &EnvironmentMetadata{
		Name:              "production",
		ClusterID:         "cluster-prod-001",
		Region:            "us-east-1",
		ComplianceLevel:   []string{"soc2", "pci-dss", "iso27001"},
		RiskTolerance:     "low",
		MaxConcurrentDeps: 10,
		AutoScaling:       true,
		MonitoringEnabled: true,
		LastUpdated:       time.Now(),
	}
}

// GetEnvironmentMetadata retrieves metadata for an environment
func (m *MockDeploymentSystem) GetEnvironmentMetadata(environment string) (*EnvironmentMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := fmt.Sprintf("[DeploymentSystem] Retrieving metadata for environment: %s", environment)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	metadata, exists := m.environments[environment]
	if !exists {
		return nil, fmt.Errorf("environment not found: %s", environment)
	}

	return metadata, nil
}

// ReportPolicyStatus reports the status of a deployed policy
func (m *MockDeploymentSystem) ReportPolicyStatus(namespace, policyName, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[DeploymentSystem] Reporting policy status for namespace '%s': policy='%s', status='%s'",
		namespace, policyName, status)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	policyStatus := &PolicyStatus{
		Namespace:    namespace,
		PolicyName:   policyName,
		Status:       status,
		DeployedAt:   time.Now(),
		LastChecked:  time.Now(),
		HealthStatus: m.deriveHealthStatus(status),
	}

	m.policyStatus[namespace] = policyStatus
	return nil
}

// GetPolicyStatus retrieves the status of a policy for a namespace
func (m *MockDeploymentSystem) GetPolicyStatus(namespace string) (*PolicyStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := fmt.Sprintf("[DeploymentSystem] Querying policy status for namespace: %s", namespace)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	status, exists := m.policyStatus[namespace]
	if !exists {
		return nil, fmt.Errorf("no policy status found for namespace: %s", namespace)
	}

	return status, nil
}

// ListAllPolicyStatuses returns all policy statuses across environments
func (m *MockDeploymentSystem) ListAllPolicyStatuses() []*PolicyStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := "[DeploymentSystem] Listing all policy statuses"
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	statuses := make([]*PolicyStatus, 0, len(m.policyStatus))
	for _, status := range m.policyStatus {
		statuses = append(statuses, status)
	}

	return statuses
}

// UpdateEnvironmentMetadata updates metadata for an environment
func (m *MockDeploymentSystem) UpdateEnvironmentMetadata(environment string, metadata *EnvironmentMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[DeploymentSystem] Updating metadata for environment: %s", environment)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	metadata.LastUpdated = time.Now()
	m.environments[environment] = metadata
	return nil
}

// SimulateDeployment simulates a policy deployment process
func (m *MockDeploymentSystem) SimulateDeployment(namespace, policyName string) error {
	logMsg := fmt.Sprintf("[DeploymentSystem] Simulating deployment of policy '%s' to namespace '%s'", policyName, namespace)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	// Simulate deployment stages
	stages := []string{"pending", "deploying", "deployed"}
	for _, stage := range stages {
		time.Sleep(10 * time.Millisecond) // Simulate work
		m.ReportPolicyStatus(namespace, policyName, stage)
		
		stageMsg := fmt.Sprintf("[DeploymentSystem] Deployment stage: %s", stage)
		log.Println(stageMsg)
		m.callLog = append(m.callLog, stageMsg)
	}

	return nil
}

// MarkPolicyFailed marks a policy deployment as failed
func (m *MockDeploymentSystem) MarkPolicyFailed(namespace, policyName, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[DeploymentSystem] Marking policy '%s' as failed in namespace '%s': %s",
		policyName, namespace, errorMsg)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	policyStatus := &PolicyStatus{
		Namespace:    namespace,
		PolicyName:   policyName,
		Status:       "failed",
		LastChecked:  time.Now(),
		HealthStatus: "unhealthy",
		ErrorMessage: errorMsg,
	}

	m.policyStatus[namespace] = policyStatus
	return nil
}

// deriveHealthStatus converts deployment status to health status
func (m *MockDeploymentSystem) deriveHealthStatus(status string) string {
	switch status {
	case "deployed":
		return "healthy"
	case "deploying", "pending":
		return "degraded"
	case "failed":
		return "unhealthy"
	default:
		return "unknown"
	}
}

// GetCallLog returns the log of all operations
func (m *MockDeploymentSystem) GetCallLog() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.callLog...)
}

// Reset clears all data and reinitializes defaults
func (m *MockDeploymentSystem) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.environments = make(map[string]*EnvironmentMetadata)
	m.policyStatus = make(map[string]*PolicyStatus)
	m.callLog = []string{}
	m.initializeDefaultEnvironments()
	log.Println("[DeploymentSystem] Reset: System reinitialized")
}