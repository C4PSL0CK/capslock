package api

import (
	"log"
	"net/http"
)

// SetupRoutes sets up all API routes
func (s *Server) SetupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", s.HandleHealth)

	// Environment detection
	mux.HandleFunc("/api/detect", s.HandleDetect)

	// Policy management
	mux.HandleFunc("/api/policies", s.HandleListPolicies)
	mux.HandleFunc("/api/policies/get", s.HandleGetPolicy)
	mux.HandleFunc("/api/policies/select", s.HandleSelectPolicy)

	// Conflict management
	mux.HandleFunc("/api/conflicts/detect", s.HandleDetectConflicts)
	mux.HandleFunc("/api/conflicts/resolve", s.HandleResolveConflicts)
	mux.HandleFunc("/api/conflict-audit", s.HandleConflictAuditLog)

	return mux
}

// Start starts the API server
func (s *Server) Start(addr string) error {
	mux := s.SetupRoutes()
	
	// Add logging middleware
	handler := loggingMiddleware(mux)
	
	// Add CORS middleware
	handler = corsMiddleware(handler)

	log.Printf("Starting EAPE API server on %s", addr)
	return http.ListenAndServe(addr, handler)
}

// Middleware functions

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}