package mocks

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// AppliedPolicy represents a policy that has been applied to a namespace
type AppliedPolicy struct {
	Namespace string
	Policy    *policy.PolicyTemplate
	AppliedAt time.Time
	Status    string // "active", "updating", "failed"
	Version   string
}

// MockIcapOperator simulates the ICAP Operator (Component 1)
type MockIcapOperator struct {
	mu              sync.RWMutex
	appliedPolicies map[string]*AppliedPolicy
	callLog         []string
}

// NewMockIcapOperator creates a new mock ICAP operator
func NewMockIcapOperator() *MockIcapOperator {
	return &MockIcapOperator{
		appliedPolicies: make(map[string]*AppliedPolicy),
		callLog:         []string{},
	}
}

// ApplyPolicy simulates applying a policy to a namespace via ICAP operator
func (m *MockIcapOperator) ApplyPolicy(namespace string, pol *policy.PolicyTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[ICAP] Applying policy '%s' to namespace '%s'", pol.Name, namespace)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	// Simulate policy application
	applied := &AppliedPolicy{
		Namespace: namespace,
		Policy:    pol,
		AppliedAt: time.Now(),
		Status:    "active",
		Version:   pol.Version,
	}

	m.appliedPolicies[namespace] = applied

	// Log policy details
	detailsMsg := fmt.Sprintf("[ICAP] Policy details - Scanning: %s, MaxFileSize: %s, Compliance: %v",
		pol.IcapConfig.ScanningMode,
		pol.IcapConfig.MaxFileSize,
		pol.ComplianceConfig.Standards)
	log.Println(detailsMsg)
	m.callLog = append(m.callLog, detailsMsg)

	return nil
}

// GetAppliedPolicy retrieves the currently applied policy for a namespace
func (m *MockIcapOperator) GetAppliedPolicy(namespace string) (*AppliedPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := fmt.Sprintf("[ICAP] Retrieving policy for namespace '%s'", namespace)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	applied, exists := m.appliedPolicies[namespace]
	if !exists {
		return nil, fmt.Errorf("no policy applied to namespace: %s", namespace)
	}

	return applied, nil
}

// ListAppliedPolicies returns all applied policies
func (m *MockIcapOperator) ListAppliedPolicies() []*AppliedPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := "[ICAP] Listing all applied policies"
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	policies := make([]*AppliedPolicy, 0, len(m.appliedPolicies))
	for _, p := range m.appliedPolicies {
		policies = append(policies, p)
	}

	return policies
}

// RemovePolicy simulates removing a policy from a namespace
func (m *MockIcapOperator) RemovePolicy(namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[ICAP] Removing policy from namespace '%s'", namespace)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	if _, exists := m.appliedPolicies[namespace]; !exists {
		return fmt.Errorf("no policy to remove from namespace: %s", namespace)
	}

	delete(m.appliedPolicies, namespace)
	return nil
}

// GetCallLog returns the log of all operations
func (m *MockIcapOperator) GetCallLog() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.callLog...)
}

// Reset clears all applied policies and logs
func (m *MockIcapOperator) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.appliedPolicies = make(map[string]*AppliedPolicy)
	m.callLog = []string{}
	log.Println("[ICAP] Reset: All policies cleared")
}