package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/alert"
	"github.com/objones25/go-network-security-agent/pkg/anomaly"
	"github.com/objones25/go-network-security-agent/pkg/dashboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAlertManager is a mock implementation of alert.Manager
type MockAlertManager struct {
	mock.Mock
}

func (m *MockAlertManager) ProcessAlert(a anomaly.Alert) (*alert.EnrichedAlert, error) {
	args := m.Called(a)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*alert.EnrichedAlert), args.Error(1)
}

func (m *MockAlertManager) UpdateAlertState(alertID string, state alert.AlertState) error {
	args := m.Called(alertID, state)
	return args.Error(0)
}

func (m *MockAlertManager) AssignAlert(alertID, assignee string) error {
	args := m.Called(alertID, assignee)
	return args.Error(0)
}

func (m *MockAlertManager) AddNote(alertID, note string) error {
	args := m.Called(alertID, note)
	return args.Error(0)
}

func (m *MockAlertManager) MarkFalsePositive(alertID, reason string) error {
	args := m.Called(alertID, reason)
	return args.Error(0)
}

func (m *MockAlertManager) ResolveAlert(alertID, resolution string) error {
	args := m.Called(alertID, resolution)
	return args.Error(0)
}

func (m *MockAlertManager) GetAlert(alertID string) (*alert.EnrichedAlert, error) {
	args := m.Called(alertID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*alert.EnrichedAlert), args.Error(1)
}

func (m *MockAlertManager) ListAlerts(filter alert.AlertFilter) ([]alert.EnrichedAlert, error) {
	args := m.Called(filter)
	return args.Get(0).([]alert.EnrichedAlert), args.Error(1)
}

func (m *MockAlertManager) GetStats() (alert.AlertStats, error) {
	args := m.Called()
	return args.Get(0).(alert.AlertStats), args.Error(1)
}

func (m *MockAlertManager) FindRelatedAlerts(alertID string) ([]alert.EnrichedAlert, error) {
	args := m.Called(alertID)
	return args.Get(0).([]alert.EnrichedAlert), args.Error(1)
}

func (m *MockAlertManager) CorrelateAlerts(timeWindow time.Duration) error {
	args := m.Called(timeWindow)
	return args.Error(0)
}

func (m *MockAlertManager) ConfigureNotifications(config alert.NotificationConfig) error {
	args := m.Called(config)
	return args.Error(0)
}

func (m *MockAlertManager) SendNotification(alert alert.EnrichedAlert) error {
	args := m.Called(alert)
	return args.Error(0)
}

func (m *MockAlertManager) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockAlertManager) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewDashboardServer(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)
	assert.NotNil(t, server, "Dashboard server should not be nil")
}

func TestHealthCheckEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
}

func TestCORSMiddleware(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)
	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
}

func TestMetricsEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "http_requests_total")
}

func TestListAlertsEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockAlert := anomaly.Alert{
		ID:        "test-1",
		Timestamp: time.Now(),
		Message:   "Test alert 1",
		Severity:  anomaly.SeverityWarning,
	}

	enrichedAlert := &alert.EnrichedAlert{
		Alert: mockAlert,
		State: alert.AlertStateNew,
		Tags:  []string{"test"},
	}

	mockAlerts := []alert.EnrichedAlert{*enrichedAlert}
	mockManager.On("ListAlerts", mock.Anything).Return(mockAlerts, nil)

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response []alert.EnrichedAlert
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Len(t, response, 1)
	assert.Equal(t, mockAlert.ID, response[0].Alert.ID)

	mockManager.AssertExpectations(t)
}

func TestGetAlertEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockAlert := anomaly.Alert{
		ID:        "test-1",
		Timestamp: time.Now(),
		Message:   "Test alert 1",
		Severity:  anomaly.SeverityWarning,
	}

	enrichedAlert := &alert.EnrichedAlert{
		Alert: mockAlert,
		State: alert.AlertStateNew,
		Tags:  []string{"test"},
	}

	mockManager.On("GetAlert", "test-1").Return(enrichedAlert, nil)

	req := httptest.NewRequest("GET", "/api/alerts/test-1", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response alert.EnrichedAlert
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, mockAlert.ID, response.Alert.ID)

	mockManager.AssertExpectations(t)
}

func TestGetAlertEndpoint_NotFound(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockManager.On("GetAlert", "non-existent").Return(nil, fmt.Errorf("alert not found"))

	req := httptest.NewRequest("GET", "/api/alerts/non-existent", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	mockManager.AssertExpectations(t)
}

func TestUpdateAlertStateEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockManager.On("UpdateAlertState", "test-1", alert.AlertStateAcknowledged).Return(nil)

	stateUpdate := alert.AlertStateAcknowledged
	body, _ := json.Marshal(stateUpdate)
	req := httptest.NewRequest("PUT", "/api/alerts/test-1/state", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockManager.AssertExpectations(t)
}

func TestUpdateAlertStateEndpoint_InvalidState(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	// Test with invalid JSON
	req := httptest.NewRequest("PUT", "/api/alerts/test-1/state", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid state format")
}

func TestUpdateAlertStateEndpoint_UpdateError(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockManager.On("UpdateAlertState", "test-1", alert.AlertStateAcknowledged).
		Return(fmt.Errorf("update failed"))

	stateUpdate := alert.AlertStateAcknowledged
	body, _ := json.Marshal(stateUpdate)
	req := httptest.NewRequest("PUT", "/api/alerts/test-1/state", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "update failed")
	mockManager.AssertExpectations(t)
}

func TestAssignAlertEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	assignee := "security-analyst"
	mockManager.On("AssignAlert", "test-1", assignee).Return(nil)

	body, _ := json.Marshal(assignee)
	req := httptest.NewRequest("PUT", "/api/alerts/test-1/assign", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockManager.AssertExpectations(t)
}

func TestAssignAlertEndpoint_InvalidAssignee(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	// Test with invalid JSON
	req := httptest.NewRequest("PUT", "/api/alerts/test-1/assign", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid assignee format")
}

func TestAssignAlertEndpoint_AssignError(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	assignee := "security-analyst"
	mockManager.On("AssignAlert", "test-1", assignee).
		Return(fmt.Errorf("assign failed"))

	body, _ := json.Marshal(assignee)
	req := httptest.NewRequest("PUT", "/api/alerts/test-1/assign", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "assign failed")
	mockManager.AssertExpectations(t)
}

func TestGetStatsEndpoint(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockStats := alert.AlertStats{
		TotalAlerts: 10,
		AlertsByState: map[alert.AlertState]int{
			alert.AlertStateNew:          5,
			alert.AlertStateAcknowledged: 3,
			alert.AlertStateResolved:     2,
		},
		AlertsByPriority: map[alert.AlertPriority]int{
			alert.PriorityHigh:   3,
			alert.PriorityMedium: 7,
		},
		RecentAlertCount: 5,
	}

	mockManager.On("GetStats").Return(mockStats, nil)

	req := httptest.NewRequest("GET", "/api/alerts/stats", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response alert.AlertStats
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, mockStats.TotalAlerts, response.TotalAlerts)
	assert.Equal(t, mockStats.AlertsByState, response.AlertsByState)
	assert.Equal(t, mockStats.AlertsByPriority, response.AlertsByPriority)
	assert.Equal(t, mockStats.RecentAlertCount, response.RecentAlertCount)

	mockManager.AssertExpectations(t)
}

func TestGetStatsEndpoint_Error(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockManager.On("GetStats").Return(alert.AlertStats{}, fmt.Errorf("stats failed"))

	req := httptest.NewRequest("GET", "/api/alerts/stats", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "stats failed")
	mockManager.AssertExpectations(t)
}

func TestListAlertsEndpoint_InvalidFilter(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	// Test with invalid JSON filter
	req := httptest.NewRequest("GET", "/api/alerts", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid filter format")
}

func TestListAlertsEndpoint_ListError(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	mockManager.On("ListAlerts", mock.Anything).
		Return([]alert.EnrichedAlert{}, fmt.Errorf("list failed"))

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "list failed")
	mockManager.AssertExpectations(t)
}

func TestCORSMiddleware_OptionsRequest(t *testing.T) {
	mockManager := new(MockAlertManager)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	// Register a route that will handle the OPTIONS request
	server.Router.HandleFunc("/api/alerts/{id}", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET", "OPTIONS")

	req, err := http.NewRequest("OPTIONS", "/api/alerts/test-1", nil)
	assert.NoError(t, err)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	rr := httptest.NewRecorder()
	server.Router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Methods"), "PUT")
	assert.Contains(t, rr.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
}

func TestMetricsMiddleware_PathLabels(t *testing.T) {
	mockManager := new(MockAlertManager)
	mockManager.On("GetAlert", "test-1").Return(&alert.EnrichedAlert{}, nil)
	server := dashboard.NewDashboardServer(":8080", mockManager)

	// First make a request that should be counted in metrics
	req, err := http.NewRequest("GET", "/api/alerts/test-1", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	server.Router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Then check the metrics endpoint
	metricsReq, err := http.NewRequest("GET", "/metrics", nil)
	assert.NoError(t, err)

	metricsRR := httptest.NewRecorder()
	server.Router.ServeHTTP(metricsRR, metricsReq)
	assert.Equal(t, http.StatusOK, metricsRR.Code)
	assert.Contains(t, metricsRR.Body.String(), `http_requests_total{endpoint="/api/alerts/test-1",method="GET"}`)

	mockManager.AssertExpectations(t)
}
