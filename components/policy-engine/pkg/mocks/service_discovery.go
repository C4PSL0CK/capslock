package mocks

import (
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

// ServiceMetadata represents metadata about a discovered service
type ServiceMetadata struct {
	Name        string
	Endpoint    string
	Environment string
	Status      string // "healthy", "degraded", "unhealthy"
	Load        float64 // 0.0 to 1.0
	Version     string
	LastChecked time.Time
}

// MockServiceDiscovery simulates the Service Discovery component (Component 3)
type MockServiceDiscovery struct {
	mu       sync.RWMutex
	services map[string][]*ServiceMetadata
	callLog  []string
}

// NewMockServiceDiscovery creates a new mock service discovery
func NewMockServiceDiscovery() *MockServiceDiscovery {
	mock := &MockServiceDiscovery{
		services: make(map[string][]*ServiceMetadata),
		callLog:  []string{},
	}

	// Initialize with some default services
	mock.initializeDefaultServices()
	return mock
}

// initializeDefaultServices sets up realistic service data
func (m *MockServiceDiscovery) initializeDefaultServices() {
	// Dev environment services
	m.services["dev"] = []*ServiceMetadata{
		{
			Name:        "icap-service-dev",
			Endpoint:    "http://icap-dev.default.svc.cluster.local:1344",
			Environment: "dev",
			Status:      "healthy",
			Load:        0.15,
			Version:     "1.0.0",
			LastChecked: time.Now(),
		},
		{
			Name:        "api-gateway-dev",
			Endpoint:    "http://api-gateway-dev.default.svc.cluster.local:8080",
			Environment: "dev",
			Status:      "healthy",
			Load:        0.25,
			Version:     "1.2.0",
			LastChecked: time.Now(),
		},
	}

	// Staging environment services
	m.services["staging"] = []*ServiceMetadata{
		{
			Name:        "icap-service-staging",
			Endpoint:    "http://icap-staging.default.svc.cluster.local:1344",
			Environment: "staging",
			Status:      "healthy",
			Load:        0.45,
			Version:     "1.0.1",
			LastChecked: time.Now(),
		},
		{
			Name:        "api-gateway-staging",
			Endpoint:    "http://api-gateway-staging.default.svc.cluster.local:8080",
			Environment: "staging",
			Status:      "degraded",
			Load:        0.75,
			Version:     "1.2.0",
			LastChecked: time.Now(),
		},
	}

	// Production environment services
	m.services["prod"] = []*ServiceMetadata{
		{
			Name:        "icap-service-prod-1",
			Endpoint:    "http://icap-prod-1.default.svc.cluster.local:1344",
			Environment: "prod",
			Status:      "healthy",
			Load:        0.65,
			Version:     "1.0.2",
			LastChecked: time.Now(),
		},
		{
			Name:        "icap-service-prod-2",
			Endpoint:    "http://icap-prod-2.default.svc.cluster.local:1344",
			Environment: "prod",
			Status:      "healthy",
			Load:        0.60,
			Version:     "1.0.2",
			LastChecked: time.Now(),
		},
		{
			Name:        "api-gateway-prod",
			Endpoint:    "http://api-gateway-prod.default.svc.cluster.local:8080",
			Environment: "prod",
			Status:      "healthy",
			Load:        0.55,
			Version:     "1.3.0",
			LastChecked: time.Now(),
		},
	}
}

// GetServices retrieves all services for an environment
func (m *MockServiceDiscovery) GetServices(environment string) ([]*ServiceMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := fmt.Sprintf("[ServiceDiscovery] Querying services for environment: %s", environment)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	services, exists := m.services[environment]
	if !exists {
		return []*ServiceMetadata{}, nil
	}

	// Simulate health check updates
	for _, svc := range services {
		svc.LastChecked = time.Now()
		// Randomly update load (simulate realistic behavior)
		svc.Load = m.simulateLoad(svc.Load)
	}

	return services, nil
}

// GetHealthyServices returns only healthy services for an environment
func (m *MockServiceDiscovery) GetHealthyServices(environment string) ([]*ServiceMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := fmt.Sprintf("[ServiceDiscovery] Querying healthy services for environment: %s", environment)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	allServices, exists := m.services[environment]
	if !exists {
		return []*ServiceMetadata{}, nil
	}

	healthy := make([]*ServiceMetadata, 0)
	for _, svc := range allServices {
		if svc.Status == "healthy" {
			healthy = append(healthy, svc)
		}
	}

	return healthy, nil
}

// GetServiceByName retrieves a specific service by name
func (m *MockServiceDiscovery) GetServiceByName(environment, name string) (*ServiceMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logMsg := fmt.Sprintf("[ServiceDiscovery] Looking up service '%s' in environment '%s'", name, environment)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	services, exists := m.services[environment]
	if !exists {
		return nil, fmt.Errorf("environment not found: %s", environment)
	}

	for _, svc := range services {
		if svc.Name == name {
			return svc, nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", name)
}

// RegisterService adds a new service to the discovery registry
func (m *MockServiceDiscovery) RegisterService(svc *ServiceMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[ServiceDiscovery] Registering service '%s' in environment '%s'", svc.Name, svc.Environment)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	if m.services[svc.Environment] == nil {
		m.services[svc.Environment] = []*ServiceMetadata{}
	}

	m.services[svc.Environment] = append(m.services[svc.Environment], svc)
	return nil
}

// UpdateServiceStatus updates the status of a service
func (m *MockServiceDiscovery) UpdateServiceStatus(environment, name, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logMsg := fmt.Sprintf("[ServiceDiscovery] Updating service '%s' status to '%s'", name, status)
	log.Println(logMsg)
	m.callLog = append(m.callLog, logMsg)

	services, exists := m.services[environment]
	if !exists {
		return fmt.Errorf("environment not found: %s", environment)
	}

	for _, svc := range services {
		if svc.Name == name {
			svc.Status = status
			svc.LastChecked = time.Now()
			return nil
		}
	}

	return fmt.Errorf("service not found: %s", name)
}

// simulateLoad simulates realistic load fluctuations
func (m *MockServiceDiscovery) simulateLoad(currentLoad float64) float64 {
	// Add small random variation (-0.1 to +0.1)
	variation := (rand.Float64() - 0.5) * 0.2
	newLoad := currentLoad + variation

	// Keep within bounds
	if newLoad < 0.0 {
		newLoad = 0.0
	}
	if newLoad > 1.0 {
		newLoad = 1.0
	}

	return newLoad
}

// GetCallLog returns the log of all operations
func (m *MockServiceDiscovery) GetCallLog() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.callLog...)
}

// Reset clears all services and logs
func (m *MockServiceDiscovery) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.services = make(map[string][]*ServiceMetadata)
	m.callLog = []string{}
	m.initializeDefaultServices()
	log.Println("[ServiceDiscovery] Reset: Services reinitialized")
}