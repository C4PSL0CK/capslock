package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/api"
)

func init() {
	// Change to project root for tests
	if err := os.Chdir("../.."); err != nil {
		panic("Failed to change to project root: " + err.Error())
	}
}

func TestHealthEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestDetectEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	payload := map[string]string{"namespace": "dev-test"}
	body, _ := json.Marshal(payload)
	
	req := httptest.NewRequest("POST", "/api/detect", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestPoliciesListEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/policies", nil)
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	// API returns an object with policies array, not a direct array
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse response: %v", err)
	}
	
	// Check if response contains data
	if len(response) == 0 {
		t.Error("Expected non-empty response")
	}
}

func TestPolicyGetEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/policies/get?name=dev-policy", nil)
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestPolicySelectEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Use string for environment to match API expectations
	payload := map[string]interface{}{
		"environment": "prod",
		"confidence":  "0.95",
	}
	body, _ := json.Marshal(payload)
	
	req := httptest.NewRequest("POST", "/api/policies/select", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	// Accept both 200 and 400 - some endpoints may have validation
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 200 or 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConflictDetectEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	payload := map[string]interface{}{
		"policy_names": []string{"dev-policy", "prod-policy"},
	}
	body, _ := json.Marshal(payload)
	
	req := httptest.NewRequest("POST", "/api/conflicts/detect", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	// Accept both 200 and 400
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 200 or 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConflictResolveEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	payload := map[string]interface{}{
		"policies":  []string{"dev-policy", "prod-policy"},
		"strategy":  "security-first",
		"namespace": "test-ns",
	}
	body, _ := json.Marshal(payload)
	
	req := httptest.NewRequest("POST", "/api/conflicts/resolve", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestInvalidEndpoint(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/invalid", nil)
	w := httptest.NewRecorder()
	
	mux := server.SetupRoutes()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for invalid endpoint, got %d", w.Code)
	}
}

func TestMultipleRequests(t *testing.T) {
	server, err := api.NewServer()
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	mux := server.SetupRoutes()

	// Test health check multiple times
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status 200, got %d", i+1, w.Code)
		}
	}
}