package alert

import (
	"time"

	"github.com/objones25/go-network-security-agent/pkg/anomaly"
)

// AlertState represents the current state of an alert
type AlertState string

const (
	// AlertStateNew represents a newly created alert
	AlertStateNew AlertState = "NEW"
	// AlertStateAcknowledged represents an alert that has been acknowledged by an operator
	AlertStateAcknowledged AlertState = "ACKNOWLEDGED"
	// AlertStateResolved represents an alert that has been resolved
	AlertStateResolved AlertState = "RESOLVED"
	// AlertStateDismissed represents an alert that has been dismissed as a false positive
	AlertStateDismissed AlertState = "DISMISSED"
)

// AlertPriority represents the priority level of an alert
type AlertPriority int

const (
	// PriorityLow represents low priority alerts
	PriorityLow AlertPriority = iota + 1
	// PriorityMedium represents medium priority alerts
	PriorityMedium
	// PriorityHigh represents high priority alerts
	PriorityHigh
	// PriorityCritical represents critical priority alerts
	PriorityCritical
)

// String returns the string representation of AlertPriority
func (p AlertPriority) String() string {
	switch p {
	case PriorityLow:
		return "LOW"
	case PriorityMedium:
		return "MEDIUM"
	case PriorityHigh:
		return "HIGH"
	case PriorityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// EnrichedAlert represents an alert with additional context and management information
type EnrichedAlert struct {
	// Core alert information from anomaly detection
	anomaly.Alert
	// Alert management fields
	State           AlertState             `json:"state"`
	Priority        AlertPriority          `json:"priority"`
	AssignedTo      string                 `json:"assigned_to,omitempty"`
	Notes           []string               `json:"notes,omitempty"`
	AcknowledgedAt  *time.Time             `json:"acknowledged_at,omitempty"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	RelatedAlerts   []string               `json:"related_alerts,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	EnrichmentData  map[string]interface{} `json:"enrichment_data,omitempty"`
	ResolutionNotes string                 `json:"resolution_notes,omitempty"`
	FalsePositive   bool                   `json:"false_positive"`
}

// AlertFilter defines criteria for filtering alerts
type AlertFilter struct {
	States     []AlertState  `json:"states,omitempty"`
	Priority   AlertPriority `json:"priority,omitempty"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Tags       []string      `json:"tags,omitempty"`
	AssignedTo string        `json:"assigned_to,omitempty"`
}

// AlertStats provides statistics about alerts
type AlertStats struct {
	TotalAlerts       int                   `json:"total_alerts"`
	AlertsByState     map[AlertState]int    `json:"alerts_by_state"`
	AlertsByPriority  map[AlertPriority]int `json:"alerts_by_priority"`
	AlertsByTag       map[string]int        `json:"alerts_by_tag"`
	RecentAlertCount  int                   `json:"recent_alert_count"` // Last 24 hours
	FalsePositiveRate float64               `json:"false_positive_rate"`
	AverageResolution time.Duration         `json:"average_resolution"`
	TopAlertTypes     map[string]int        `json:"top_alert_types"`
}

// NotificationConfig defines how alerts should be notified
type NotificationConfig struct {
	Email     *EmailConfig   `json:"email,omitempty"`
	Slack     *SlackConfig   `json:"slack,omitempty"`
	Webhook   *WebhookConfig `json:"webhook,omitempty"`
	Threshold AlertPriority  `json:"threshold"` // Minimum priority for notification
}

// EmailConfig defines email notification settings
type EmailConfig struct {
	Recipients []string `json:"recipients"`
	SMTPServer string   `json:"smtp_server"`
	SMTPPort   int      `json:"smtp_port"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	FromEmail  string   `json:"from_email"`
}

// SlackConfig defines Slack notification settings
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	IconEmoji  string `json:"icon_emoji"`
}

// WebhookConfig defines webhook notification settings
type WebhookConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}
