package dashboard

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/objones25/go-network-security-agent/pkg/alert"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
}

// DashboardServer represents the dashboard HTTP server
type DashboardServer struct {
	Router  *mux.Router
	server  *http.Server
	addr    string
	manager alert.Manager
}

// NewDashboardServer creates a new dashboard server
func NewDashboardServer(addr string, manager alert.Manager) *DashboardServer {
	s := &DashboardServer{
		Router:  mux.NewRouter(),
		addr:    addr,
		manager: manager,
	}
	s.setupRoutes()
	return s
}

func (s *DashboardServer) setupRoutes() {
	// Add CORS middleware
	s.Router.Use(s.corsMiddleware)
	s.Router.Use(s.metricsMiddleware)

	// API routes
	api := s.Router.PathPrefix("/api").Subrouter()

	// Health check endpoint
	api.HandleFunc("/health", s.healthCheckHandler).Methods("GET", "OPTIONS")

	// Alert management endpoints
	api.HandleFunc("/alerts", s.handleListAlerts).Methods("GET")
	api.HandleFunc("/alerts/{id}", s.handleGetAlert).Methods("GET")
	api.HandleFunc("/alerts/{id}/state", s.handleUpdateAlertState).Methods("PUT")
	api.HandleFunc("/alerts/{id}/assign", s.handleAssignAlert).Methods("PUT")
	api.HandleFunc("/alerts/stats", s.handleGetStats).Methods("GET")

	// Metrics endpoint
	s.Router.Handle("/metrics", promhttp.Handler())
}

func (s *DashboardServer) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	var filter alert.AlertFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil && r.Body != http.NoBody {
		http.Error(w, "Invalid filter format", http.StatusBadRequest)
		return
	}

	alerts, err := s.manager.ListAlerts(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(alerts)
}

func (s *DashboardServer) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	alert, err := s.manager.GetAlert(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(alert)
}

func (s *DashboardServer) handleUpdateAlertState(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var state alert.AlertState
	if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
		http.Error(w, "Invalid state format", http.StatusBadRequest)
		return
	}

	if err := s.manager.UpdateAlertState(id, state); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *DashboardServer) handleAssignAlert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var assignee string
	if err := json.NewDecoder(r.Body).Decode(&assignee); err != nil {
		http.Error(w, "Invalid assignee format", http.StatusBadRequest)
		return
	}

	if err := s.manager.AssignAlert(id, assignee); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *DashboardServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.manager.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(stats)
}

func (s *DashboardServer) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		next.ServeHTTP(w, r)
	})
}

func (s *DashboardServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *DashboardServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{"status": "ok"}
	json.NewEncoder(w).Encode(response)
}

func (s *DashboardServer) Start() error {
	s.server = &http.Server{
		Addr:    s.addr,
		Handler: s.Router,
	}
	return s.server.ListenAndServe()
}

func (s *DashboardServer) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
