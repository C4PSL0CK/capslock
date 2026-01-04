package mocks

import (
	"testing"
	"time"
)

func TestNewMockDeploymentSystem(t *testing.T) {
	mock := NewMockDeploymentSystem()
	if mock == nil {
		t.Fatal("NewMockDeploymentSystem returned nil")
	}

	// Should have default environments
	metadata, err := mock.GetEnvironmentMetadata("dev")
	if err != nil {
		t.Errorf("Expected default dev environment: %v", err)
	}
	if metadata == nil {
		t.Error("Dev metadata should not be nil")
	}
}

func TestGetEnvironmentMetadata(t *testing.T) {
	mock := NewMockDeploymentSystem()

	tests := []struct {
		env      string
		expected string
	}{
		{"dev", "development"},
		{"staging", "staging"},
		{"prod", "production"},
	}

	for _, tt := range tests {
		metadata, err := mock.GetEnvironmentMetadata(tt.env)
		if err != nil {
			t.Errorf("GetEnvironmentMetadata(%s) failed: %v", tt.env, err)
			continue
		}

		if metadata.Name != tt.expected {
			t.Errorf("Expected name '%s', got '%s'", tt.expected, metadata.Name)
		}
	}
}

func TestGetEnvironmentMetadata_NotFound(t *testing.T) {
	mock := NewMockDeploymentSystem()

	_, err := mock.GetEnvironmentMetadata("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent environment")
	}
}

func TestReportPolicyStatus(t *testing.T) {
	mock := NewMockDeploymentSystem()

	err := mock.ReportPolicyStatus("test-ns", "test-policy", "deployed")
	if err != nil {
		t.Fatalf("ReportPolicyStatus failed: %v", err)
	}

	status, err := mock.GetPolicyStatus("test-ns")
	if err != nil {
		t.Fatalf("GetPolicyStatus failed: %v", err)
	}

	if status.PolicyName != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got '%s'", status.PolicyName)
	}

	if status.Status != "deployed" {
		t.Errorf("Expected status 'deployed', got '%s'", status.Status)
	}

	if status.HealthStatus != "healthy" {
		t.Errorf("Expected health status 'healthy', got '%s'", status.HealthStatus)
	}
}

func TestGetPolicyStatus_NotFound(t *testing.T) {
	mock := NewMockDeploymentSystem()

	_, err := mock.GetPolicyStatus("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent namespace")
	}
}

func TestListAllPolicyStatuses(t *testing.T) {
	mock := NewMockDeploymentSystem()

	mock.ReportPolicyStatus("ns1", "policy1", "deployed")
	mock.ReportPolicyStatus("ns2", "policy2", "deploying")

	statuses := mock.ListAllPolicyStatuses()
	if len(statuses) != 2 {
		t.Errorf("Expected 2 policy statuses, got %d", len(statuses))
	}
}

func TestUpdateEnvironmentMetadata(t *testing.T) {
	mock := NewMockDeploymentSystem()

	newMetadata := &EnvironmentMetadata{
		Name:              "test-env",
		ClusterID:         "test-cluster",
		Region:            "us-west-1",
		ComplianceLevel:   []string{"test"},
		RiskTolerance:     "medium",
		MaxConcurrentDeps: 20,
		AutoScaling:       false,
		MonitoringEnabled: true,
	}

	err := mock.UpdateEnvironmentMetadata("test", newMetadata)
	if err != nil {
		t.Fatalf("UpdateEnvironmentMetadata failed: %v", err)
	}

	retrieved, err := mock.GetEnvironmentMetadata("test")
	if err != nil {
		t.Fatalf("GetEnvironmentMetadata failed: %v", err)
	}

	if retrieved.ClusterID != "test-cluster" {
		t.Errorf("Expected cluster ID 'test-cluster', got '%s'", retrieved.ClusterID)
	}
}

func TestSimulateDeployment(t *testing.T) {
	mock := NewMockDeploymentSystem()

	err := mock.SimulateDeployment("test-ns", "test-policy")
	if err != nil {
		t.Fatalf("SimulateDeployment failed: %v", err)
	}

	// Give it a moment to complete
	time.Sleep(100 * time.Millisecond)

	status, err := mock.GetPolicyStatus("test-ns")
	if err != nil {
		t.Fatalf("GetPolicyStatus failed: %v", err)
	}

	if status.Status != "deployed" {
		t.Errorf("Expected final status 'deployed', got '%s'", status.Status)
	}
}

func TestMarkPolicyFailed(t *testing.T) {
	mock := NewMockDeploymentSystem()

	errMsg := "deployment timeout"
	err := mock.MarkPolicyFailed("test-ns", "test-policy", errMsg)
	if err != nil {
		t.Fatalf("MarkPolicyFailed failed: %v", err)
	}

	status, err := mock.GetPolicyStatus("test-ns")
	if err != nil {
		t.Fatalf("GetPolicyStatus failed: %v", err)
	}

	if status.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", status.Status)
	}

	if status.ErrorMessage != errMsg {
		t.Errorf("Expected error message '%s', got '%s'", errMsg, status.ErrorMessage)
	}

	if status.HealthStatus != "unhealthy" {
		t.Errorf("Expected health status 'unhealthy', got '%s'", status.HealthStatus)
	}
}

func TestDeploymentSystemGetCallLog(t *testing.T) {
	mock := NewMockDeploymentSystem()

	mock.GetEnvironmentMetadata("dev")
	log := mock.GetCallLog()

	if len(log) == 0 {
		t.Error("Call log should not be empty")
	}
}

func TestDeploymentSystemReset(t *testing.T) {
	mock := NewMockDeploymentSystem()

	mock.ReportPolicyStatus("test-ns", "test-policy", "deployed")
	mock.Reset()

	// Policy status should be cleared
	_, err := mock.GetPolicyStatus("test-ns")
	if err == nil {
		t.Error("Policy status should have been cleared after reset")
	}

	// Default environments should be back
	_, err = mock.GetEnvironmentMetadata("dev")
	if err != nil {
		t.Error("Default environments should be reinitialized after reset")
	}
}