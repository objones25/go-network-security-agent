package unit

import (
	"context"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/alert"
	"github.com/objones25/go-network-security-agent/pkg/anomaly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)
	require.NotNil(t, manager)
}

func TestManagerLifecycle(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	// Test Start
	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)

	// Test double start
	err = manager.Start(ctx)
	assert.Error(t, err)

	// Test Stop
	err = manager.Stop()
	require.NoError(t, err)

	// Test double stop
	err = manager.Stop()
	assert.Error(t, err)
}

func TestAlertStateTransitions(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Create and process test alert
	testAlert := anomaly.Alert{
		ID:        "test-alert-1",
		Timestamp: time.Now(),
		Severity:  anomaly.SeverityCritical,
		Message:   "Test critical alert",
	}

	enriched, err := manager.ProcessAlert(testAlert)
	require.NoError(t, err)
	require.NotNil(t, enriched)

	// Test state transitions
	tests := []struct {
		name          string
		state         alert.AlertState
		expectedState alert.AlertState
	}{
		{"Acknowledge", alert.AlertStateAcknowledged, alert.AlertStateAcknowledged},
		{"Resolve", alert.AlertStateResolved, alert.AlertStateResolved},
		{"Dismiss", alert.AlertStateDismissed, alert.AlertStateDismissed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.UpdateAlertState(testAlert.ID, tt.state)
			require.NoError(t, err)

			updated, err := manager.GetAlert(testAlert.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedState, updated.State)
		})
	}
}

func TestAlertPriorityMapping(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	tests := []struct {
		name             string
		severity         anomaly.AlertSeverity
		expectedPriority alert.AlertPriority
	}{
		{"Critical Severity", anomaly.SeverityCritical, alert.PriorityCritical},
		{"Warning Severity", anomaly.SeverityWarning, alert.PriorityHigh},
		{"Info Severity", anomaly.SeverityInfo, alert.PriorityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAlert := anomaly.Alert{
				ID:        "test-" + tt.name,
				Timestamp: time.Now(),
				Severity:  tt.severity,
				Message:   "Test alert",
			}

			enriched, err := manager.ProcessAlert(testAlert)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedPriority, enriched.Priority)
		})
	}
}

func TestAlertRetrieval(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Test non-existent alert
	_, err = manager.GetAlert("non-existent")
	assert.Error(t, err)

	// Create and retrieve alert
	testAlert := anomaly.Alert{
		ID:        "test-retrieval",
		Timestamp: time.Now(),
		Severity:  anomaly.SeverityWarning,
		Message:   "Test alert",
	}

	enriched, err := manager.ProcessAlert(testAlert)
	require.NoError(t, err)

	retrieved, err := manager.GetAlert(testAlert.ID)
	require.NoError(t, err)
	assert.Equal(t, enriched.ID, retrieved.ID)
	assert.Equal(t, enriched.Priority, retrieved.Priority)
}

func TestAlertNotes(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Create test alert
	testAlert := anomaly.Alert{
		ID:        "test-notes",
		Timestamp: time.Now(),
		Severity:  anomaly.SeverityWarning,
		Message:   "Test alert",
	}

	_, err = manager.ProcessAlert(testAlert)
	require.NoError(t, err)

	// Add notes
	notes := []string{
		"First investigation note",
		"Follow-up observation",
		"Resolution note",
	}

	for _, note := range notes {
		err := manager.AddNote(testAlert.ID, note)
		require.NoError(t, err)
	}

	// Verify notes
	alert, err := manager.GetAlert(testAlert.ID)
	require.NoError(t, err)
	assert.Equal(t, notes, alert.Notes)
}

func TestAlertAssignment(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Create test alert
	testAlert := anomaly.Alert{
		ID:        "test-assignment",
		Timestamp: time.Now(),
		Severity:  anomaly.SeverityWarning,
		Message:   "Test alert",
	}

	_, err = manager.ProcessAlert(testAlert)
	require.NoError(t, err)

	// Test assignment
	assignee := "security-team-lead"
	err = manager.AssignAlert(testAlert.ID, assignee)
	require.NoError(t, err)

	alert, err := manager.GetAlert(testAlert.ID)
	require.NoError(t, err)
	assert.Equal(t, assignee, alert.AssignedTo)
}
