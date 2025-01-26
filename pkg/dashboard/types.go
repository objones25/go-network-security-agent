package dashboard

import (
	"time"

	"github.com/objones25/go-network-security-agent/pkg/alert"
)

// AlertFilter represents the criteria for filtering alerts
type AlertFilter struct {
	StartTime  time.Time           `json:"startTime"`
	EndTime    time.Time           `json:"endTime"`
	States     []alert.AlertState  `json:"states,omitempty"`
	Priority   alert.AlertPriority `json:"priority,omitempty"`
	AssignedTo string              `json:"assignedTo,omitempty"`
	Tags       []string            `json:"tags,omitempty"`
}

// AlertStats represents alert statistics
type AlertStats struct {
	TotalAlerts           int                         `json:"totalAlerts"`
	AlertsByState         map[alert.AlertState]int    `json:"alertsByState"`
	AlertsByPriority      map[alert.AlertPriority]int `json:"alertsByPriority"`
	FalsePositiveRate     float64                     `json:"falsePositiveRate"`
	AverageResolutionTime time.Duration               `json:"averageResolutionTime"`
}

// Settings represents the system settings
type Settings struct {
	Notifications struct {
		Email struct {
			Enabled     bool                `json:"enabled"`
			Recipients  string              `json:"recipients"`
			MinPriority alert.AlertPriority `json:"minPriority"`
		} `json:"email"`
		Slack struct {
			Enabled bool   `json:"enabled"`
			Webhook string `json:"webhook"`
			Channel string `json:"channel"`
		} `json:"slack"`
	} `json:"notifications"`
	Enrichment struct {
		GeoIP struct {
			Enabled        bool `json:"enabled"`
			UpdateInterval int  `json:"updateInterval"`
		} `json:"geoip"`
		ThreatIntel struct {
			Enabled        bool   `json:"enabled"`
			UpdateInterval int    `json:"updateInterval"`
			APIKey         string `json:"apiKey"`
		} `json:"threatIntel"`
	} `json:"enrichment"`
	Retention struct {
		AlertRetentionDays int `json:"alertRetentionDays"`
		LogsRetentionDays  int `json:"logsRetentionDays"`
	} `json:"retention"`
	Correlation struct {
		TimeWindow    int     `json:"timeWindow"`
		MinSimilarity float64 `json:"minSimilarity"`
	} `json:"correlation"`
}
