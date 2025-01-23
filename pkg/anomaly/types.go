package anomaly

import (
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
)

// AlertSeverity represents the severity level of an alert
type AlertSeverity int

const (
	SeverityInfo AlertSeverity = iota
	SeverityWarning
	SeverityCritical
)

// DetectionContext holds all relevant data for anomaly detection
type DetectionContext struct {
	// Current snapshot being analyzed
	CurrentSnapshot capture.StatsSnapshot
	// Previous snapshot for comparison
	PreviousSnapshot capture.StatsSnapshot
	// Time window for analysis
	Window time.Duration
	// Additional metadata
	Metadata map[string]interface{}
}

// Alert represents a detected anomaly
type Alert struct {
	ID          string                 // Unique identifier
	RuleID      string                 // ID of the rule that generated this alert
	Timestamp   time.Time              // When the anomaly was detected
	Severity    AlertSeverity          // Alert severity level
	Message     string                 // Human-readable description
	Context     map[string]interface{} // Additional context about the alert
	Score       float64                // Anomaly score (0-1)
	Source      string                 // Source of the anomaly (IP, protocol, etc.)
	Destination string                 // Destination if applicable
	Protocol    string                 // Protocol involved
	MetricName  string                 // Name of the metric that triggered the alert
	MetricValue float64                // Value that triggered the alert
	Threshold   float64                // Threshold that was exceeded
}

// RuleCategory represents the type of anomaly being detected
type RuleCategory string

// Rule categories
const (
	CategoryTrafficVolume   RuleCategory = "traffic_volume"
	CategoryPortScan        RuleCategory = "port_scan"
	CategoryDDoS            RuleCategory = "ddos"
	CategoryDataExfil       RuleCategory = "data_exfil"
	CategoryProtocolAnomaly RuleCategory = "protocol_anomaly"
	CategoryMalware         RuleCategory = "malware"
	CategoryBruteForce      RuleCategory = "brute_force"
	CategoryConnectionSpike RuleCategory = "connection_spike"
	CategoryLateralMovement RuleCategory = "lateral_movement"
	CategoryTimeAnomaly     RuleCategory = "time_anomaly"
	CategoryGeoAnomaly      RuleCategory = "geo_anomaly"
)

// Rule defines a single anomaly detection rule
type Rule struct {
	ID          string                 // Unique identifier
	Name        string                 // Human-readable name
	Description string                 // Detailed description
	Severity    AlertSeverity          // Default severity level
	Category    RuleCategory           // Rule category
	Condition   Condition              // Detection condition
	Threshold   float64                // Detection threshold
	Enabled     bool                   // Whether the rule is active
	Metadata    map[string]interface{} // Additional rule metadata
}

// Condition defines the interface for rule conditions
type Condition interface {
	// Evaluate checks if the condition is met given the detection context
	Evaluate(ctx *DetectionContext) bool
	// Description returns a human-readable description of the condition
	Description() string
}

// DetectorConfig holds configuration for the anomaly detector
type DetectorConfig struct {
	// Minimum confidence score for generating alerts
	MinConfidenceScore float64
	// How often to run detection checks
	DetectionInterval time.Duration
	// Maximum number of alerts to store in history
	MaxAlertHistory int
	// Whether to enable adaptive thresholds
	AdaptiveThresholds bool
	// Base thresholds for different metrics
	Thresholds DetectorThresholds
	// Alert correlation settings
	CorrelationWindow time.Duration
	MinCorrelation    float64
}

// DetectorThresholds defines thresholds for different types of anomalies
type DetectorThresholds struct {
	// Traffic volume thresholds
	PacketRateThreshold     float64 // Packets per second
	ByteRateThreshold       float64 // Bytes per second
	ConnectionRateThreshold float64 // New connections per second

	// Statistical thresholds
	ZScoreThreshold float64 // Standard deviations from mean
	IQRThreshold    float64 // Interquartile range multiplier

	// Protocol-specific thresholds
	TCPSynRateThreshold float64 // SYN packets per second
	UDPFloodThreshold   float64 // UDP packets per second
	ICMPRateThreshold   float64 // ICMP packets per second

	// Port scan detection
	PortScanThreshold float64 // Unique ports per second

	// DDoS detection
	DDoSPacketThreshold float64 // Packets per second for DDoS
	DDoSByteThreshold   float64 // Bytes per second for DDoS

	// Data exfiltration
	DataExfilThreshold float64 // Bytes per second for data exfil
}

// DetectorMetrics holds current detector performance metrics
type DetectorMetrics struct {
	// Alert counts by severity
	InfoAlerts      int
	WarningAlerts   int
	CriticalAlerts  int
	AlertsGenerated int // Total number of alerts generated

	// Detection performance
	AverageDetectionTime time.Duration
	FalsePositiveRate    float64
	DetectionLatency     time.Duration

	// Resource usage
	CPUUsage    float64
	MemoryUsage float64

	// Rule metrics
	ActiveRules   int
	RuleHits      map[string]int
	RuleLatencies map[string]time.Duration
}

// DetectorStatus represents the current state of the detector
type DetectorStatus struct {
	IsRunning       bool
	LastCheck       time.Time
	CurrentLoad     float64
	HealthScore     float64
	ActiveRules     int
	AlertsGenerated int
	LastError       error
}
