package mocks

import (
	"testing"
)

func TestNewMockServiceDiscovery(t *testing.T) {
	mock := NewMockServiceDiscovery()
	if mock == nil {
		t.Fatal("NewMockServiceDiscovery returned nil")
	}

	// Should have default services
	devServices, _ := mock.GetServices("dev")
	if len(devServices) == 0 {
		t.Error("Expected default dev services to be initialized")
	}
}

func TestGetServices(t *testing.T) {
	mock := NewMockServiceDiscovery()

	services, err := mock.GetServices("dev")
	if err != nil {
		t.Fatalf("GetServices failed: %v", err)
	}

	if len(services) == 0 {
		t.Error("Expected at least one service in dev environment")
	}

	// Verify service structure
	for _, svc := range services {
		if svc.Name == "" {
			t.Error("Service name should not be empty")
		}
		if svc.Endpoint == "" {
			t.Error("Service endpoint should not be empty")
		}
		if svc.Status == "" {
			t.Error("Service status should not be empty")
		}
	}
}

func TestGetHealthyServices(t *testing.T) {
	mock := NewMockServiceDiscovery()

	healthy, err := mock.GetHealthyServices("prod")
	if err != nil {
		t.Fatalf("GetHealthyServices failed: %v", err)
	}

	// All returned services should be healthy
	for _, svc := range healthy {
		if svc.Status != "healthy" {
			t.Errorf("Expected healthy service, got status: %s", svc.Status)
		}
	}
}

func TestGetServiceByName(t *testing.T) {
	mock := NewMockServiceDiscovery()

	svc, err := mock.GetServiceByName("dev", "icap-service-dev")
	if err != nil {
		t.Fatalf("GetServiceByName failed: %v", err)
	}

	if svc.Name != "icap-service-dev" {
		t.Errorf("Expected service name 'icap-service-dev', got '%s'", svc.Name)
	}
}

func TestGetServiceByName_NotFound(t *testing.T) {
	mock := NewMockServiceDiscovery()

	_, err := mock.GetServiceByName("dev", "non-existent-service")
	if err == nil {
		t.Error("Expected error for non-existent service")
	}
}

func TestRegisterService(t *testing.T) {
	mock := NewMockServiceDiscovery()

	newService := &ServiceMetadata{
		Name:        "test-service",
		Endpoint:    "http://test.svc:8080",
		Environment: "test",
		Status:      "healthy",
		Load:        0.5,
		Version:     "1.0.0",
	}

	err := mock.RegisterService(newService)
	if err != nil {
		t.Fatalf("RegisterService failed: %v", err)
	}

	// Verify it was registered
	services, _ := mock.GetServices("test")
	if len(services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(services))
	}
}

func TestUpdateServiceStatus(t *testing.T) {
	mock := NewMockServiceDiscovery()

	err := mock.UpdateServiceStatus("dev", "icap-service-dev", "unhealthy")
	if err != nil {
		t.Fatalf("UpdateServiceStatus failed: %v", err)
	}

	svc, _ := mock.GetServiceByName("dev", "icap-service-dev")
	if svc.Status != "unhealthy" {
		t.Errorf("Expected status 'unhealthy', got '%s'", svc.Status)
	}
}

func TestServiceDiscoveryGetCallLog(t *testing.T) {
	mock := NewMockServiceDiscovery()

	mock.GetServices("dev")
	log := mock.GetCallLog()

	if len(log) == 0 {
		t.Error("Call log should not be empty")
	}
}

func TestServiceDiscoveryReset(t *testing.T) {
	mock := NewMockServiceDiscovery()

	// Add a custom service
	newService := &ServiceMetadata{
		Name:        "custom-service",
		Environment: "custom",
		Status:      "healthy",
	}
	mock.RegisterService(newService)

	mock.Reset()

	// Custom service should be gone
	_, err := mock.GetServiceByName("custom", "custom-service")
	if err == nil {
		t.Error("Custom service should have been cleared after reset")
	}

	// Default services should be back
	devServices, _ := mock.GetServices("dev")
	if len(devServices) == 0 {
		t.Error("Default services should be reinitialized after reset")
	}
}