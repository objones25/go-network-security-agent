package integration

import (
	"context"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/alert"
	"github.com/objones25/go-network-security-agent/pkg/anomaly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertProcessingEndToEnd(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Create a series of related alerts
	alerts := []anomaly.Alert{
		{
			ID:        "e2e-1",
			Timestamp: time.Now(),
			Severity:  anomaly.SeverityWarning,
			Message:   "Port scan detected",
			Source:    "192.168.1.100",
			Protocol:  "TCP",
		},
		{
			ID:        "e2e-2",
			Timestamp: time.Now().Add(time.Second),
			Severity:  anomaly.SeverityWarning,
			Message:   "Suspicious connection attempt",
			Source:    "192.168.1.100",
			Protocol:  "TCP",
		},
		{
			ID:        "e2e-3",
			Timestamp: time.Now().Add(2 * time.Second),
			Severity:  anomaly.SeverityCritical,
			Message:   "Unauthorized access attempt",
			Source:    "192.168.1.100",
			Protocol:  "TCP",
		},
	}

	// Process alerts
	for _, a := range alerts {
		enriched, err := manager.ProcessAlert(a)
		require.NoError(t, err)
		require.NotNil(t, enriched)
		assert.NotEmpty(t, enriched.Tags)
	}

	// Test correlation
	err = manager.CorrelateAlerts(time.Minute)
	require.NoError(t, err)

	// Verify related alerts
	related, err := manager.FindRelatedAlerts("e2e-1")
	require.NoError(t, err)
	assert.NotEmpty(t, related)

	// Test alert lifecycle
	err = manager.UpdateAlertState("e2e-1", alert.AlertStateAcknowledged)
	require.NoError(t, err)

	err = manager.AssignAlert("e2e-1", "security-analyst")
	require.NoError(t, err)

	err = manager.AddNote("e2e-1", "Investigating port scan activity")
	require.NoError(t, err)

	err = manager.ResolveAlert("e2e-1", "False positive - authorized security scan")
	require.NoError(t, err)

	// Verify final state
	finalAlert, err := manager.GetAlert("e2e-1")
	require.NoError(t, err)
	assert.Equal(t, alert.AlertStateResolved, finalAlert.State)
	assert.Equal(t, "security-analyst", finalAlert.AssignedTo)
	assert.NotEmpty(t, finalAlert.Notes)
	assert.NotNil(t, finalAlert.ResolvedAt)
}

func TestAlertFilteringAndStats(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Create alerts with different priorities and times
	baseTime := time.Now().Add(-24 * time.Hour)
	alerts := []struct {
		alert    anomaly.Alert
		state    alert.AlertState
		assignee string
	}{
		{
			alert: anomaly.Alert{
				ID:        "filter-1",
				Timestamp: baseTime,
				Severity:  anomaly.SeverityCritical,
				Message:   "Critical security breach",
			},
			state:    alert.AlertStateResolved,
			assignee: "team-lead",
		},
		{
			alert: anomaly.Alert{
				ID:        "filter-2",
				Timestamp: baseTime.Add(12 * time.Hour),
				Severity:  anomaly.SeverityWarning,
				Message:   "Suspicious activity",
			},
			state:    alert.AlertStateAcknowledged,
			assignee: "analyst-1",
		},
		{
			alert: anomaly.Alert{
				ID:        "filter-3",
				Timestamp: baseTime.Add(23 * time.Hour),
				Severity:  anomaly.SeverityInfo,
				Message:   "System notification",
			},
			state:    alert.AlertStateNew,
			assignee: "",
		},
	}

	// Process and update alerts
	for _, a := range alerts {
		_, err := manager.ProcessAlert(a.alert)
		require.NoError(t, err)

		if a.state != alert.AlertStateNew {
			err = manager.UpdateAlertState(a.alert.ID, a.state)
			require.NoError(t, err)
		}

		if a.assignee != "" {
			err = manager.AssignAlert(a.alert.ID, a.assignee)
			require.NoError(t, err)
		}
	}

	// Test filtering
	tests := []struct {
		name          string
		filter        alert.AlertFilter
		expectedCount int
	}{
		{
			name: "Filter by time range",
			filter: alert.AlertFilter{
				StartTime: baseTime.Add(6 * time.Hour),
				EndTime:   baseTime.Add(22 * time.Hour),
			},
			expectedCount: 1,
		},
		{
			name: "Filter by state",
			filter: alert.AlertFilter{
				States:    []alert.AlertState{alert.AlertStateResolved},
				StartTime: baseTime,
				EndTime:   baseTime.Add(24 * time.Hour),
			},
			expectedCount: 1,
		},
		{
			name: "Filter by assignee",
			filter: alert.AlertFilter{
				AssignedTo: "team-lead",
				StartTime:  baseTime,
				EndTime:    baseTime.Add(24 * time.Hour),
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := manager.ListAlerts(tt.filter)
			require.NoError(t, err)
			assert.Len(t, filtered, tt.expectedCount)
		})
	}

	// Test statistics
	stats, err := manager.GetStats()
	require.NoError(t, err)

	assert.Equal(t, 3, stats.TotalAlerts)
	assert.Equal(t, 1, stats.AlertsByState[alert.AlertStateNew])
	assert.Equal(t, 1, stats.AlertsByState[alert.AlertStateAcknowledged])
	assert.Equal(t, 1, stats.AlertsByState[alert.AlertStateResolved])
}

func TestNotificationConfiguration(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Configure notifications with mock settings
	config := alert.NotificationConfig{
		Threshold: alert.PriorityHigh,
		// Skip actual notification configs for testing
	}

	err = manager.ConfigureNotifications(config)
	require.NoError(t, err)

	// Create test alerts with different priorities
	alerts := []anomaly.Alert{
		{
			ID:        "notify-1",
			Timestamp: time.Now(),
			Severity:  anomaly.SeverityCritical,
			Message:   "Critical security event",
		},
		{
			ID:        "notify-2",
			Timestamp: time.Now(),
			Severity:  anomaly.SeverityInfo,
			Message:   "Informational event",
		},
	}

	// Process alerts and verify they're handled correctly
	for _, a := range alerts {
		enriched, err := manager.ProcessAlert(a)
		require.NoError(t, err)
		require.NotNil(t, enriched)

		// Verify priority-based notification threshold
		if enriched.Priority >= config.Threshold {
			assert.Equal(t, alert.PriorityCritical, enriched.Priority)
		} else {
			assert.Equal(t, alert.PriorityMedium, enriched.Priority)
		}
	}
}

func TestAlertEnrichmentAndCorrelation(t *testing.T) {
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Create a sequence of related alerts
	alerts := []anomaly.Alert{
		{
			ID:        "enrich-1",
			Timestamp: time.Now(),
			Severity:  anomaly.SeverityWarning,
			Message:   "Failed login attempt",
			Source:    "192.168.1.100",
			Protocol:  "SSH",
		},
		{
			ID:        "enrich-2",
			Timestamp: time.Now().Add(time.Minute),
			Severity:  anomaly.SeverityWarning,
			Message:   "Multiple failed logins",
			Source:    "192.168.1.100",
			Protocol:  "SSH",
		},
		{
			ID:        "enrich-3",
			Timestamp: time.Now().Add(2 * time.Minute),
			Severity:  anomaly.SeverityCritical,
			Message:   "Possible brute force attack",
			Source:    "192.168.1.100",
			Protocol:  "SSH",
		},
	}

	// Process alerts and verify enrichment
	for _, a := range alerts {
		enriched, err := manager.ProcessAlert(a)
		require.NoError(t, err)
		require.NotNil(t, enriched)

		// Verify enrichment data
		assert.NotNil(t, enriched.EnrichmentData)
		assert.NotEmpty(t, enriched.Tags)

		// Verify protocol-specific enrichment
		if protocolInfo, ok := enriched.EnrichmentData["protocol_info"].(map[string]interface{}); ok {
			assert.NotEmpty(t, protocolInfo)
		}
	}

	// Perform correlation
	err = manager.CorrelateAlerts(5 * time.Minute)
	require.NoError(t, err)

	// Verify correlation results
	for _, a := range alerts {
		related, err := manager.FindRelatedAlerts(a.ID)
		require.NoError(t, err)
		assert.NotEmpty(t, related)
	}
}
