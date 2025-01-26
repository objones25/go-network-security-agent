package alert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/anomaly"
)

// Manager defines the interface for alert management
type Manager interface {
	// Alert Processing
	ProcessAlert(alert anomaly.Alert) (*EnrichedAlert, error)
	UpdateAlertState(alertID string, state AlertState) error
	AssignAlert(alertID, assignee string) error
	AddNote(alertID, note string) error
	MarkFalsePositive(alertID string, reason string) error
	ResolveAlert(alertID, resolution string) error

	// Alert Retrieval
	GetAlert(alertID string) (*EnrichedAlert, error)
	ListAlerts(filter AlertFilter) ([]EnrichedAlert, error)
	GetStats() (AlertStats, error)

	// Alert Correlation
	FindRelatedAlerts(alertID string) ([]EnrichedAlert, error)
	CorrelateAlerts(timeWindow time.Duration) error

	// Notification Management
	ConfigureNotifications(config NotificationConfig) error
	SendNotification(alert EnrichedAlert) error

	// Lifecycle Management
	Start(ctx context.Context) error
	Stop() error
}

// DefaultManager implements the Manager interface
type DefaultManager struct {
	mu sync.RWMutex

	// Core components
	alerts       map[string]*EnrichedAlert
	notifyConfig NotificationConfig
	correlator   *AlertCorrelator
	enricher     *AlertEnricher
	notifier     *AlertNotifier

	// Channels
	alertChan    chan anomaly.Alert
	responseChan chan error
	done         chan struct{}

	// State
	ctx       context.Context
	cancel    context.CancelFunc
	isRunning bool
	startTime time.Time
}

// NewManager creates a new alert manager instance
func NewManager() (*DefaultManager, error) {
	m := &DefaultManager{
		alerts:       make(map[string]*EnrichedAlert),
		alertChan:    make(chan anomaly.Alert, 1000),
		responseChan: make(chan error, 1000),
		done:         make(chan struct{}),
	}

	// Initialize components
	m.correlator = NewAlertCorrelator()
	m.enricher = NewAlertEnricher()
	m.notifier = NewAlertNotifier()

	return m, nil
}

// Start begins alert processing
func (m *DefaultManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning {
		return fmt.Errorf("alert manager is already running")
	}

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.isRunning = true
	m.startTime = time.Now()

	// Start alert processing goroutine
	go m.processAlerts()

	return nil
}

// Stop halts alert processing
func (m *DefaultManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return fmt.Errorf("alert manager is not running")
	}

	m.cancel()
	close(m.done)
	m.isRunning = false

	return nil
}

// ProcessAlert handles a new alert from anomaly detection
func (m *DefaultManager) ProcessAlert(alert anomaly.Alert) (*EnrichedAlert, error) {
	if !m.isRunning {
		return nil, fmt.Errorf("alert manager is not running")
	}

	// Convert to enriched alert
	enriched := &EnrichedAlert{
		Alert:    alert,
		State:    AlertStateNew,
		Priority: m.calculatePriority(alert),
		Tags:     []string{},
	}

	// Enrich alert with additional context
	if err := m.enricher.EnrichAlert(enriched); err != nil {
		return nil, fmt.Errorf("failed to enrich alert: %v", err)
	}

	// Store alert
	m.mu.Lock()
	m.alerts[alert.ID] = enriched
	m.mu.Unlock()

	// Correlate with existing alerts
	if err := m.correlator.CorrelateAlert(enriched); err != nil {
		return nil, fmt.Errorf("failed to correlate alert: %v", err)
	}

	// Send notification if needed
	if err := m.notifier.NotifyAlert(*enriched); err != nil {
		return nil, fmt.Errorf("failed to send notification: %v", err)
	}

	return enriched, nil
}

// UpdateAlertState updates the state of an alert
func (m *DefaultManager) UpdateAlertState(alertID string, state AlertState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	alert.State = state

	switch state {
	case AlertStateAcknowledged:
		now := time.Now()
		alert.AcknowledgedAt = &now
	case AlertStateResolved:
		now := time.Now()
		alert.ResolvedAt = &now
	}

	return nil
}

// AssignAlert assigns an alert to a user
func (m *DefaultManager) AssignAlert(alertID, assignee string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	alert.AssignedTo = assignee
	return nil
}

// AddNote adds a note to an alert
func (m *DefaultManager) AddNote(alertID, note string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	alert.Notes = append(alert.Notes, note)
	return nil
}

// MarkFalsePositive marks an alert as a false positive
func (m *DefaultManager) MarkFalsePositive(alertID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	alert.FalsePositive = true
	alert.State = AlertStateDismissed
	alert.ResolutionNotes = reason

	now := time.Now()
	alert.ResolvedAt = &now

	return nil
}

// ResolveAlert marks an alert as resolved
func (m *DefaultManager) ResolveAlert(alertID, resolution string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	alert.State = AlertStateResolved
	alert.ResolutionNotes = resolution

	now := time.Now()
	alert.ResolvedAt = &now

	return nil
}

// GetAlert retrieves a specific alert
func (m *DefaultManager) GetAlert(alertID string) (*EnrichedAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}

	return alert, nil
}

// ListAlerts retrieves alerts based on filter criteria
func (m *DefaultManager) ListAlerts(filter AlertFilter) ([]EnrichedAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []EnrichedAlert

	for _, alert := range m.alerts {
		if m.matchesFilter(alert, filter) {
			results = append(results, *alert)
		}
	}

	return results, nil
}

// GetStats returns current alert statistics
func (m *DefaultManager) GetStats() (AlertStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := AlertStats{
		TotalAlerts:      len(m.alerts),
		AlertsByState:    make(map[AlertState]int),
		AlertsByPriority: make(map[AlertPriority]int),
		AlertsByTag:      make(map[string]int),
		TopAlertTypes:    make(map[string]int),
	}

	var totalResolutionTime time.Duration
	resolvedCount := 0
	falsePositives := 0
	recentAlerts := 0
	dayAgo := time.Now().Add(-24 * time.Hour)

	for _, alert := range m.alerts {
		// Count by state
		stats.AlertsByState[alert.State]++

		// Count by priority
		stats.AlertsByPriority[alert.Priority]++

		// Count by tags
		for _, tag := range alert.Tags {
			stats.AlertsByTag[tag]++
		}

		// Count alert types
		stats.TopAlertTypes[alert.MetricName]++

		// Calculate resolution time for resolved alerts
		if alert.State == AlertStateResolved && alert.ResolvedAt != nil {
			resolvedCount++
			totalResolutionTime += alert.ResolvedAt.Sub(alert.Timestamp)
		}

		// Count false positives
		if alert.FalsePositive {
			falsePositives++
		}

		// Count recent alerts
		if alert.Timestamp.After(dayAgo) {
			recentAlerts++
		}
	}

	// Calculate averages and rates
	if resolvedCount > 0 {
		stats.AverageResolution = totalResolutionTime / time.Duration(resolvedCount)
	}
	if len(m.alerts) > 0 {
		stats.FalsePositiveRate = float64(falsePositives) / float64(len(m.alerts))
	}
	stats.RecentAlertCount = recentAlerts

	return stats, nil
}

// FindRelatedAlerts finds alerts related to the given alert
func (m *DefaultManager) FindRelatedAlerts(alertID string) ([]EnrichedAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alert, exists := m.alerts[alertID]
	if !exists {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}

	var related []EnrichedAlert
	for _, relatedID := range alert.RelatedAlerts {
		if relatedAlert, exists := m.alerts[relatedID]; exists {
			related = append(related, *relatedAlert)
		}
	}

	return related, nil
}

// CorrelateAlerts performs correlation analysis on alerts within the time window
func (m *DefaultManager) CorrelateAlerts(timeWindow time.Duration) error {
	return m.correlator.CorrelateAlerts(m.alerts, timeWindow)
}

// ConfigureNotifications updates notification settings
func (m *DefaultManager) ConfigureNotifications(config NotificationConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.notifyConfig = config
	return m.notifier.Configure(config)
}

// SendNotification sends a notification for an alert
func (m *DefaultManager) SendNotification(alert EnrichedAlert) error {
	return m.notifier.NotifyAlert(alert)
}

// Helper functions

// calculatePriority determines the priority of an alert based on severity and context
func (m *DefaultManager) calculatePriority(alert anomaly.Alert) AlertPriority {
	switch alert.Severity {
	case anomaly.SeverityCritical:
		return PriorityCritical
	case anomaly.SeverityWarning:
		return PriorityHigh
	default:
		return PriorityMedium
	}
}

// matchesFilter checks if an alert matches the given filter criteria
func (m *DefaultManager) matchesFilter(alert *EnrichedAlert, filter AlertFilter) bool {
	// Check time range
	if !alert.Timestamp.After(filter.StartTime) && !alert.Timestamp.Equal(filter.StartTime) {
		return false
	}
	if !alert.Timestamp.Before(filter.EndTime) && !alert.Timestamp.Equal(filter.EndTime) {
		return false
	}

	// Check states if specified
	if len(filter.States) > 0 {
		stateMatch := false
		for _, state := range filter.States {
			if alert.State == state {
				stateMatch = true
				break
			}
		}
		if !stateMatch {
			return false
		}
	}

	// Check priority if specified
	if filter.Priority != 0 && alert.Priority != filter.Priority {
		return false
	}

	// Check assignee if specified
	if filter.AssignedTo != "" && alert.AssignedTo != filter.AssignedTo {
		return false
	}

	// Check tags if specified
	if len(filter.Tags) > 0 {
		for _, tag := range filter.Tags {
			tagFound := false
			for _, alertTag := range alert.Tags {
				if tag == alertTag {
					tagFound = true
					break
				}
			}
			if !tagFound {
				return false
			}
		}
	}

	return true
}

// processAlerts handles the alert processing loop
func (m *DefaultManager) processAlerts() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case alert := <-m.alertChan:
			enriched, err := m.ProcessAlert(alert)
			if err != nil {
				m.responseChan <- fmt.Errorf("failed to process alert: %v", err)
				continue
			}

			// Perform automatic correlation
			if err := m.correlator.CorrelateAlert(enriched); err != nil {
				m.responseChan <- fmt.Errorf("failed to correlate alert: %v", err)
				continue
			}

			m.responseChan <- nil
		}
	}
}
