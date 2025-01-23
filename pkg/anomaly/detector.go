package anomaly

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/objones25/go-network-security-agent/pkg/capture"
)

// Detector defines the interface for anomaly detection
type Detector interface {
	// Core detection methods
	Detect(snapshot capture.StatsSnapshot) []Alert
	AddRule(rule Rule) error
	RemoveRule(ruleID string) error
	GetRule(ruleID string) (Rule, bool)
	ListRules() []Rule

	// Configuration
	Configure(config DetectorConfig) error
	SetThresholds(thresholds DetectorThresholds) error
	GetThresholds() DetectorThresholds

	// State management
	Start(ctx context.Context) error
	Stop() error
	Status() DetectorStatus
	Metrics() DetectorMetrics

	// Alert management
	GetAlerts(since time.Time) []Alert
	ClearAlerts()
}

// DefaultDetector implements the Detector interface
type DefaultDetector struct {
	mu sync.RWMutex

	// Configuration
	config     DetectorConfig
	thresholds DetectorThresholds

	// State
	status    DetectorStatus
	metrics   DetectorMetrics
	isRunning bool
	ctx       context.Context
	cancel    context.CancelFunc
	startTime time.Time
	lastCheck time.Time

	// Components
	rules          map[string]Rule
	alerts         []Alert
	baselineMgr    *baseline.Manager
	logger         *log.Logger
	snapshotBuffer []capture.StatsSnapshot

	// Channels
	alertChan chan Alert
	done      chan struct{}
}

// NewDetector creates a new anomaly detector with default configuration
func NewDetector(baselineMgr *baseline.Manager) (*DefaultDetector, error) {
	if baselineMgr == nil {
		return nil, fmt.Errorf("baseline manager is required")
	}

	d := &DefaultDetector{
		rules:          make(map[string]Rule),
		alerts:         make([]Alert, 0),
		baselineMgr:    baselineMgr,
		logger:         log.New(log.Writer(), "[AnomalyDetector] ", log.LstdFlags),
		snapshotBuffer: make([]capture.StatsSnapshot, 0),
		alertChan:      make(chan Alert, 1000),
		done:           make(chan struct{}),
		metrics: DetectorMetrics{
			RuleHits:      make(map[string]int),
			RuleLatencies: make(map[string]time.Duration),
		},
	}

	// Set default configuration
	d.config = DetectorConfig{
		MinConfidenceScore: 0.8,
		DetectionInterval:  time.Second * 10,
		MaxAlertHistory:    1000,
		AdaptiveThresholds: true,
		CorrelationWindow:  time.Minute * 5,
		MinCorrelation:     0.7,
	}

	// Set default thresholds
	d.thresholds = DetectorThresholds{
		PacketRateThreshold:     10000,  // 10k packets/sec
		ByteRateThreshold:       1e6,    // 1 MB/sec
		ConnectionRateThreshold: 100,    // 100 new conns/sec
		ZScoreThreshold:         3.0,    // 3 standard deviations
		IQRThreshold:            1.5,    // 1.5 * IQR
		TCPSynRateThreshold:     1000,   // 1k SYN/sec
		UDPFloodThreshold:       5000,   // 5k UDP/sec
		ICMPRateThreshold:       100,    // 100 ICMP/sec
		PortScanThreshold:       50,     // 50 ports/sec
		DDoSPacketThreshold:     100000, // 100k packets/sec
		DDoSByteThreshold:       1e7,    // 10 MB/sec
		DataExfilThreshold:      1e6,    // 1 MB/sec
	}

	return d, nil
}

// Configure updates the detector configuration
func (d *DefaultDetector) Configure(config DetectorConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate configuration
	if config.DetectionInterval < time.Second {
		return fmt.Errorf("detection interval must be at least 1 second")
	}
	if config.MaxAlertHistory < 1 {
		return fmt.Errorf("max alert history must be positive")
	}
	if config.MinConfidenceScore < 0 || config.MinConfidenceScore > 1 {
		return fmt.Errorf("confidence score must be between 0 and 1")
	}

	d.config = config
	return nil
}

// SetThresholds updates the detection thresholds
func (d *DefaultDetector) SetThresholds(thresholds DetectorThresholds) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate thresholds
	if thresholds.ZScoreThreshold <= 0 {
		return fmt.Errorf("z-score threshold must be positive")
	}
	if thresholds.IQRThreshold <= 0 {
		return fmt.Errorf("IQR threshold must be positive")
	}

	d.thresholds = thresholds
	return nil
}

// GetThresholds returns the current detection thresholds
func (d *DefaultDetector) GetThresholds() DetectorThresholds {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.thresholds
}

// Start begins the anomaly detection process
func (d *DefaultDetector) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isRunning {
		return fmt.Errorf("detector is already running")
	}

	d.ctx, d.cancel = context.WithCancel(ctx)
	d.isRunning = true
	d.startTime = time.Now()
	d.status.IsRunning = true

	// Start detection loop
	go d.detectionLoop()

	// Start alert processor
	go d.processAlerts()

	d.logger.Printf("Anomaly detector started")
	return nil
}

// Stop halts the anomaly detection process
func (d *DefaultDetector) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isRunning {
		return fmt.Errorf("detector is not running")
	}

	d.cancel()
	close(d.done)
	d.isRunning = false
	d.status.IsRunning = false

	d.logger.Printf("Anomaly detector stopped")
	return nil
}

// Status returns the current detector status
func (d *DefaultDetector) Status() DetectorStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.status
}

// Metrics returns the current detector metrics
func (d *DefaultDetector) Metrics() DetectorMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.metrics
}

// AddRule adds a new detection rule
func (d *DefaultDetector) AddRule(rule Rule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.rules[rule.ID]; exists {
		return fmt.Errorf("rule with ID %s already exists", rule.ID)
	}

	if rule.Condition == nil {
		return fmt.Errorf("rule must have a condition")
	}

	d.rules[rule.ID] = rule
	d.metrics.ActiveRules = len(d.rules)
	return nil
}

// RemoveRule removes a detection rule
func (d *DefaultDetector) RemoveRule(ruleID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.rules[ruleID]; !exists {
		return fmt.Errorf("rule with ID %s not found", ruleID)
	}

	delete(d.rules, ruleID)
	d.metrics.ActiveRules = len(d.rules)
	return nil
}

// GetRule retrieves a rule by ID
func (d *DefaultDetector) GetRule(ruleID string) (Rule, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rule, exists := d.rules[ruleID]
	return rule, exists
}

// ListRules returns all configured rules
func (d *DefaultDetector) ListRules() []Rule {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rules := make([]Rule, 0, len(d.rules))
	for _, rule := range d.rules {
		rules = append(rules, rule)
	}
	return rules
}

// GetAlerts returns alerts since the specified time
func (d *DefaultDetector) GetAlerts(since time.Time) []Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	alerts := make([]Alert, 0)
	for _, alert := range d.alerts {
		if alert.Timestamp.After(since) {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// ClearAlerts removes all stored alerts
func (d *DefaultDetector) ClearAlerts() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.alerts = make([]Alert, 0)
}

// Detect performs anomaly detection on a snapshot
func (d *DefaultDetector) Detect(snapshot capture.StatsSnapshot) []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.isRunning {
		return nil
	}

	startTime := time.Now()
	alerts := make([]Alert, 0)

	// Create detection context
	ctx := &DetectionContext{
		CurrentSnapshot: snapshot,
		Window:          d.config.DetectionInterval,
		Metadata:        make(map[string]interface{}),
	}

	// Get previous snapshot if available
	if len(d.snapshotBuffer) > 0 {
		ctx.PreviousSnapshot = d.snapshotBuffer[len(d.snapshotBuffer)-1]
	}

	// Evaluate each rule
	for _, rule := range d.rules {
		if !rule.Enabled {
			continue
		}

		ruleStart := time.Now()
		if rule.Condition.Evaluate(ctx) {
			alert := Alert{
				ID:         fmt.Sprintf("alert-%d", time.Now().UnixNano()),
				RuleID:     rule.ID,
				Timestamp:  time.Now(),
				Severity:   rule.Severity,
				Message:    fmt.Sprintf("Rule '%s' triggered: %s", rule.Name, rule.Description),
				Context:    make(map[string]interface{}),
				Score:      1.0, // TODO: Implement proper scoring
				MetricName: string(rule.Category),
			}
			alerts = append(alerts, alert)
			d.metrics.RuleHits[rule.ID]++

			// Store alert in detector's alert list
			d.alerts = append(d.alerts, alert)
			// Trim alerts if exceeding maximum history
			if len(d.alerts) > d.config.MaxAlertHistory {
				d.alerts = d.alerts[1:]
			}
			// Update metrics
			switch alert.Severity {
			case SeverityInfo:
				d.metrics.InfoAlerts++
			case SeverityWarning:
				d.metrics.WarningAlerts++
			case SeverityCritical:
				d.metrics.CriticalAlerts++
			}
			d.metrics.AlertsGenerated++
		}
		d.metrics.RuleLatencies[rule.ID] = time.Since(ruleStart)
	}

	// Update metrics
	d.metrics.AverageDetectionTime = time.Since(startTime)
	d.lastCheck = time.Now()

	// Buffer snapshot for future comparison
	d.snapshotBuffer = append(d.snapshotBuffer, snapshot)
	if len(d.snapshotBuffer) > 10 {
		d.snapshotBuffer = d.snapshotBuffer[1:]
	}

	return alerts
}

// detectionLoop runs the main detection loop
func (d *DefaultDetector) detectionLoop() {
	ticker := time.NewTicker(d.config.DetectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			if alerts := d.processDetection(); len(alerts) > 0 {
				for _, alert := range alerts {
					select {
					case d.alertChan <- alert:
					default:
						d.logger.Printf("Alert channel full, dropping alert: %s", alert.Message)
					}
				}
			}
		}
	}
}

// processDetection handles a single detection cycle
func (d *DefaultDetector) processDetection() []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get latest stats from baseline manager
	stats := d.baselineMgr.GetCurrentStats()
	if stats == nil {
		d.logger.Printf("Warning: No current stats available from baseline manager")
		return nil
	}

	// Skip detection if baseline is not healthy or still learning
	if !d.baselineMgr.IsHealthy() {
		issues := d.baselineMgr.GetIssues()
		d.logger.Printf("Skipping detection - baseline not healthy: %v", issues)
		return nil
	}

	alerts := make([]Alert, 0)
	startTime := time.Now()

	// Evaluate each enabled rule
	for _, rule := range d.rules {
		if !rule.Enabled {
			continue
		}

		ruleStart := time.Now()
		if rule.Condition.Evaluate(&DetectionContext{
			CurrentSnapshot: *stats,
			Window:          d.config.DetectionInterval,
			Metadata: map[string]interface{}{
				"baseline_health": d.baselineMgr.GetHealth(),
			},
		}) {
			// Calculate anomaly score based on baseline deviation
			score := d.calculateAnomalyScore(stats, rule)

			// Only generate alert if score exceeds confidence threshold
			if score >= d.config.MinConfidenceScore {
				alert := Alert{
					ID:         fmt.Sprintf("alert-%d", time.Now().UnixNano()),
					RuleID:     rule.ID,
					Timestamp:  time.Now(),
					Severity:   rule.Severity,
					Message:    fmt.Sprintf("Rule '%s' triggered: %s", rule.Name, rule.Description),
					Score:      score,
					Protocol:   d.determineAnomalousProtocol(stats),
					MetricName: string(rule.Category),
				}

				// Add relevant threshold and value information
				switch rule.Category {
				case CategoryTrafficVolume:
					alert.MetricValue = float64(stats.TotalPackets)
					alert.Threshold = d.thresholds.PacketRateThreshold
				case CategoryProtocolAnomaly:
					alert.MetricValue = float64(stats.PacketsByProtocol["TCP"])
					alert.Threshold = d.thresholds.TCPSynRateThreshold
				case CategoryDDoS:
					alert.MetricValue = float64(stats.TotalPackets)
					alert.Threshold = d.thresholds.DDoSPacketThreshold
				}

				alerts = append(alerts, alert)
			}
		}
		d.metrics.RuleLatencies[rule.ID] = time.Since(ruleStart)
	}

	// Update detection metrics
	d.metrics.AverageDetectionTime = time.Since(startTime)
	d.lastCheck = time.Now()

	return alerts
}

// calculateAnomalyScore determines how anomalous the current behavior is
func (d *DefaultDetector) calculateAnomalyScore(stats *capture.StatsSnapshot, rule Rule) float64 {
	baselineHealth := d.baselineMgr.GetHealth()

	// Weight the score based on baseline confidence
	confidenceWeight := baselineHealth.Confidence
	if confidenceWeight < 0.5 {
		confidenceWeight = 0.5 // Minimum weight to avoid completely discarding detections
	}

	var score float64
	switch rule.Category {
	case CategoryTrafficVolume:
		// Use baseline's variance tracking for packet rate
		hourlyStats := d.baselineMgr.GetHourlyStats(time.Now().Hour())
		if hourlyStats != nil && hourlyStats.Variance != nil {
			score = hourlyStats.Variance.GetZScore(float64(stats.TotalPackets))
			score = math.Abs(score) / d.thresholds.ZScoreThreshold
		}

	case CategoryProtocolAnomaly:
		// Compare protocol distribution to baseline
		if tcpStats, ok := d.baselineMgr.GetProtocolStats("TCP"); ok && tcpStats.PacketVariance != nil {
			score = tcpStats.PacketVariance.GetZScore(float64(stats.PacketsByProtocol["TCP"]))
			score = math.Abs(score) / d.thresholds.ZScoreThreshold
		}

	case CategoryDDoS:
		// Use multiple indicators for DDoS detection
		var indicators []float64

		// 1. Packet rate anomaly
		hourlyStats := d.baselineMgr.GetHourlyStats(time.Now().Hour())
		if hourlyStats != nil && hourlyStats.Variance != nil {
			packetScore := hourlyStats.Variance.GetZScore(float64(stats.TotalPackets))
			indicators = append(indicators, math.Abs(packetScore)/d.thresholds.ZScoreThreshold)
		}

		// 2. Protocol distribution anomaly
		if tcpStats, ok := d.baselineMgr.GetProtocolStats("TCP"); ok && tcpStats.PacketVariance != nil {
			tcpScore := tcpStats.PacketVariance.GetZScore(float64(stats.PacketsByProtocol["TCP"]))
			indicators = append(indicators, math.Abs(tcpScore)/d.thresholds.ZScoreThreshold)
		}

		// Combine indicators with max function to catch the strongest signal
		if len(indicators) > 0 {
			score = 0
			for _, ind := range indicators {
				if ind > score {
					score = ind
				}
			}
		}

	default:
		score = 0.8 // Default score for other categories
	}

	// Apply confidence weighting
	score *= confidenceWeight

	// Normalize to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// determineAnomalousProtocol identifies which protocol is showing anomalous behavior
func (d *DefaultDetector) determineAnomalousProtocol(stats *capture.StatsSnapshot) string {
	maxDeviation := 0.0
	anomalousProto := "UNKNOWN"

	// Check each protocol's deviation from baseline
	for proto := range stats.PacketsByProtocol {
		if protoStats, ok := d.baselineMgr.GetProtocolStats(proto); ok && protoStats.PacketVariance != nil {
			zscore := math.Abs(protoStats.PacketVariance.GetZScore(float64(stats.PacketsByProtocol[proto])))
			if zscore > maxDeviation {
				maxDeviation = zscore
				anomalousProto = proto
			}
		}
	}

	return anomalousProto
}

// processAlerts handles alert processing and storage
func (d *DefaultDetector) processAlerts() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case alert := <-d.alertChan:
			d.mu.Lock()
			d.alerts = append(d.alerts, alert)
			// Trim alerts if exceeding maximum history
			if len(d.alerts) > d.config.MaxAlertHistory {
				d.alerts = d.alerts[1:]
			}
			// Update metrics
			switch alert.Severity {
			case SeverityInfo:
				d.metrics.InfoAlerts++
			case SeverityWarning:
				d.metrics.WarningAlerts++
			case SeverityCritical:
				d.metrics.CriticalAlerts++
			}
			d.metrics.AlertsGenerated++
			d.mu.Unlock()
		}
	}
}
