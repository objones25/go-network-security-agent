package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"sync"
	"text/template"
	"time"
)

// AlertNotifier handles the delivery of alert notifications
type AlertNotifier struct {
	mu sync.RWMutex

	// Configuration
	config NotificationConfig

	// Templates
	emailTemplate   *template.Template
	slackTemplate   *template.Template
	webhookTemplate *template.Template

	// Notification stats
	stats NotificationStats

	// Rate limiting
	rateLimiter *time.Ticker
	lastNotify  map[string]time.Time
}

// NotificationStats tracks notification delivery statistics
type NotificationStats struct {
	TotalSent      int
	FailedSent     int
	LastSent       time.Time
	ByPriority     map[AlertPriority]int
	ByChannel      map[string]int
	AverageLatency time.Duration
}

// NewAlertNotifier creates a new alert notifier
func NewAlertNotifier() *AlertNotifier {
	return &AlertNotifier{
		lastNotify: make(map[string]time.Time),
		stats: NotificationStats{
			ByPriority: make(map[AlertPriority]int),
			ByChannel:  make(map[string]int),
		},
		rateLimiter: time.NewTicker(time.Second), // Basic rate limiting
	}
}

// Configure updates the notifier configuration
func (n *AlertNotifier) Configure(config NotificationConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Validate configuration
	if err := n.validateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	n.config = config

	// Initialize templates
	if err := n.initializeTemplates(); err != nil {
		return fmt.Errorf("failed to initialize templates: %v", err)
	}

	return nil
}

// NotifyAlert sends notifications for an alert based on configuration
func (n *AlertNotifier) NotifyAlert(alert EnrichedAlert) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Check if alert meets notification threshold
	if alert.Priority < n.config.Threshold {
		return nil
	}

	// Check rate limiting
	if !n.shouldNotify(alert) {
		return nil
	}

	startTime := time.Now()
	var errors []error

	// Send email notifications
	if n.config.Email != nil {
		if err := n.sendEmailNotification(alert); err != nil {
			errors = append(errors, fmt.Errorf("email notification failed: %v", err))
		}
	}

	// Send Slack notifications
	if n.config.Slack != nil {
		if err := n.sendSlackNotification(alert); err != nil {
			errors = append(errors, fmt.Errorf("slack notification failed: %v", err))
		}
	}

	// Send webhook notifications
	if n.config.Webhook != nil {
		if err := n.sendWebhookNotification(alert); err != nil {
			errors = append(errors, fmt.Errorf("webhook notification failed: %v", err))
		}
	}

	// Update statistics
	n.updateStats(alert, startTime, len(errors) == 0)

	if len(errors) > 0 {
		return fmt.Errorf("notification errors: %v", errors)
	}

	return nil
}

// shouldNotify checks if we should send a notification based on rate limiting
func (n *AlertNotifier) shouldNotify(alert EnrichedAlert) bool {
	key := fmt.Sprintf("%s-%s", alert.ID, alert.Priority)
	lastTime, exists := n.lastNotify[key]

	if !exists {
		n.lastNotify[key] = time.Now()
		return true
	}

	// Rate limit based on priority
	var minInterval time.Duration
	switch alert.Priority {
	case PriorityCritical:
		minInterval = time.Minute
	case PriorityHigh:
		minInterval = time.Minute * 5
	case PriorityMedium:
		minInterval = time.Minute * 15
	default:
		minInterval = time.Hour
	}

	if time.Since(lastTime) < minInterval {
		return false
	}

	n.lastNotify[key] = time.Now()
	return true
}

// sendEmailNotification sends an email notification
func (n *AlertNotifier) sendEmailNotification(alert EnrichedAlert) error {
	if n.config.Email == nil {
		return nil
	}

	var body bytes.Buffer
	if err := n.emailTemplate.Execute(&body, alert); err != nil {
		return fmt.Errorf("failed to execute email template: %v", err)
	}

	// Configure email
	auth := smtp.PlainAuth("",
		n.config.Email.Username,
		n.config.Email.Password,
		n.config.Email.SMTPServer,
	)

	// Prepare email message
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: [%s] Security Alert: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n%s",
		n.config.Email.FromEmail,
		n.config.Email.Recipients[0],
		alert.Priority,
		alert.Message,
		body.String(),
	)

	// Send email
	err := smtp.SendMail(
		fmt.Sprintf("%s:%d", n.config.Email.SMTPServer, n.config.Email.SMTPPort),
		auth,
		n.config.Email.FromEmail,
		n.config.Email.Recipients,
		[]byte(msg),
	)

	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// sendSlackNotification sends a Slack notification
func (n *AlertNotifier) sendSlackNotification(alert EnrichedAlert) error {
	if n.config.Slack == nil {
		return nil
	}

	var body bytes.Buffer
	if err := n.slackTemplate.Execute(&body, alert); err != nil {
		return fmt.Errorf("failed to execute slack template: %v", err)
	}

	// Prepare Slack message
	message := map[string]interface{}{
		"channel":    n.config.Slack.Channel,
		"username":   n.config.Slack.Username,
		"icon_emoji": n.config.Slack.IconEmoji,
		"text":       body.String(),
		"attachments": []map[string]interface{}{
			{
				"color": n.getAlertColor(alert.Priority),
				"fields": []map[string]interface{}{
					{
						"title": "Priority",
						"value": alert.Priority.String(),
						"short": true,
					},
					{
						"title": "Source",
						"value": alert.Source,
						"short": true,
					},
					{
						"title": "Protocol",
						"value": alert.Protocol,
						"short": true,
					},
					{
						"title": "Time",
						"value": alert.Timestamp.Format(time.RFC3339),
						"short": true,
					},
				},
			},
		},
	}

	// Send to Slack
	jsonBody, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %v", err)
	}

	resp, err := http.Post(n.config.Slack.WebhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to send slack message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}

// sendWebhookNotification sends a webhook notification
func (n *AlertNotifier) sendWebhookNotification(alert EnrichedAlert) error {
	if n.config.Webhook == nil {
		return nil
	}

	var body bytes.Buffer
	if err := n.webhookTemplate.Execute(&body, alert); err != nil {
		return fmt.Errorf("failed to execute webhook template: %v", err)
	}

	// Create request
	req, err := http.NewRequest(n.config.Webhook.Method, n.config.Webhook.URL, &body)
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %v", err)
	}

	// Add headers
	for key, value := range n.config.Webhook.Headers {
		req.Header.Add(key, value)
	}

	// Send request
	client := &http.Client{Timeout: time.Second * 10}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-success status: %d", resp.StatusCode)
	}

	return nil
}

// updateStats updates notification statistics
func (n *AlertNotifier) updateStats(alert EnrichedAlert, startTime time.Time, success bool) {
	n.stats.TotalSent++
	if !success {
		n.stats.FailedSent++
	}
	n.stats.LastSent = time.Now()
	n.stats.ByPriority[alert.Priority]++

	latency := time.Since(startTime)
	if n.stats.AverageLatency == 0 {
		n.stats.AverageLatency = latency
	} else {
		n.stats.AverageLatency = (n.stats.AverageLatency + latency) / 2
	}

	if n.config.Email != nil {
		n.stats.ByChannel["email"]++
	}
	if n.config.Slack != nil {
		n.stats.ByChannel["slack"]++
	}
	if n.config.Webhook != nil {
		n.stats.ByChannel["webhook"]++
	}
}

// validateConfig validates the notification configuration
func (n *AlertNotifier) validateConfig(config NotificationConfig) error {
	if config.Email != nil {
		if config.Email.SMTPServer == "" || config.Email.SMTPPort == 0 {
			return fmt.Errorf("invalid email configuration: missing SMTP settings")
		}
		if len(config.Email.Recipients) == 0 {
			return fmt.Errorf("invalid email configuration: no recipients specified")
		}
	}

	if config.Slack != nil {
		if config.Slack.WebhookURL == "" {
			return fmt.Errorf("invalid slack configuration: missing webhook URL")
		}
		if config.Slack.Channel == "" {
			return fmt.Errorf("invalid slack configuration: missing channel")
		}
	}

	if config.Webhook != nil {
		if config.Webhook.URL == "" {
			return fmt.Errorf("invalid webhook configuration: missing URL")
		}
		if config.Webhook.Method == "" {
			return fmt.Errorf("invalid webhook configuration: missing HTTP method")
		}
	}

	return nil
}

// initializeTemplates initializes notification templates
func (n *AlertNotifier) initializeTemplates() error {
	// Email template
	emailTmpl := `
<!DOCTYPE html>
<html>
<body>
    <h2>Security Alert: {{.Message}}</h2>
    <p><strong>Priority:</strong> {{.Priority}}</p>
    <p><strong>Time:</strong> {{.Timestamp}}</p>
    <p><strong>Source:</strong> {{.Source}}</p>
    <p><strong>Protocol:</strong> {{.Protocol}}</p>
    <hr>
    <h3>Details:</h3>
    <pre>{{.Context}}</pre>
</body>
</html>`

	var err error
	n.emailTemplate, err = template.New("email").Parse(emailTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %v", err)
	}

	// Slack template
	slackTmpl := `
:warning: *Security Alert*
{{.Message}}
*Priority:* {{.Priority}}
*Time:* {{.Timestamp}}
*Source:* {{.Source}}
*Protocol:* {{.Protocol}}`

	n.slackTemplate, err = template.New("slack").Parse(slackTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse slack template: %v", err)
	}

	// Webhook template (JSON)
	webhookTmpl := `{
    "alert": {
        "id": "{{.ID}}",
        "message": "{{.Message}}",
        "priority": "{{.Priority}}",
        "timestamp": "{{.Timestamp}}",
        "source": "{{.Source}}",
        "protocol": "{{.Protocol}}",
        "context": {{.Context}}
    }
}`

	n.webhookTemplate, err = template.New("webhook").Parse(webhookTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse webhook template: %v", err)
	}

	return nil
}

// getAlertColor returns the color for Slack attachments based on priority
func (n *AlertNotifier) getAlertColor(priority AlertPriority) string {
	switch priority {
	case PriorityCritical:
		return "#FF0000" // Red
	case PriorityHigh:
		return "#FFA500" // Orange
	case PriorityMedium:
		return "#FFFF00" // Yellow
	default:
		return "#00FF00" // Green
	}
}

// GetNotificationStats returns current notification statistics
func (n *AlertNotifier) GetNotificationStats() NotificationStats {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.stats
}
