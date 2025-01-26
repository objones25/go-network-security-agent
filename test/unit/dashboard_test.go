package unit

import (
	"context"
	"encoding/json"
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
