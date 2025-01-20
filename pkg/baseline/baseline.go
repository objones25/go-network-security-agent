package baseline

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
)

// Config holds configuration for the baseline learning system
type Config struct {
	// Initial learning period before generating alerts
	InitialLearningPeriod time.Duration

	// How often to update baseline calculations
	UpdateInterval time.Duration

	// Minimum number of samples needed before baseline is considered valid
	MinSamples int

	// EWMA alpha values for different time scales
	ShortTermAlpha  float64 // For 5-minute averages
	MediumTermAlpha float64 // For hourly averages
	LongTermAlpha   float64 // For daily averages

	// Z-score threshold for anomaly detection
	AnomalyThreshold float64

	// Persistence configuration
	PersistenceEnabled bool          // Whether to enable persistence
	PersistencePath    string        // Directory to store persistence files
	CheckpointInterval time.Duration // How often to save state
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		InitialLearningPeriod: 24 * time.Hour,
		UpdateInterval:        time.Hour,
		MinSamples:            1000,
		ShortTermAlpha:        0.3,  // More weight on recent values
		MediumTermAlpha:       0.1,  // Balanced weight
		LongTermAlpha:         0.05, // More weight on history
		AnomalyThreshold:      3.0,  // 3 standard deviations
		PersistenceEnabled:    true,
		PersistencePath:       "data/baseline",
		CheckpointInterval:    15 * time.Minute,
	}
}

// BaselineHealth tracks core health metrics specifically for the baseline component
type BaselineHealth struct {
	// Learning State
	LearningProgress float64   // Progress through initial learning period (0-100%)
	LearningPhase    string    // Current learning phase (Initial/Active/Stable)
	DataPoints       int       // Number of data points processed
	LastUpdate       time.Time // Time of last baseline update

	// Baseline Quality
	Confidence float64 // Overall confidence in baseline stability (0-1)
	Stability  float64 // Measure of baseline stability over time (0-1)
	Coverage   float64 // Data coverage percentage across time windows
	Maturity   float64 // Baseline maturity score (0-1)

	// Statistical Health
	MeanStability       float64 // Stability of mean values
	VarianceStability   float64 // Stability of variance measurements
	DistributionQuality float64 // Quality of statistical distribution
	StationarityScore   float64 // Measure of baseline stationarity

	// Temporal Coverage
	TimeWindowCoverage map[string]float64 // Coverage by time window (hourly/daily/monthly)
	TemporalStability  float64            // Stability across time periods
	SeasonalityScore   float64            // Quality of seasonality detection
	DataFreshness      float64            // Age of most recent data points

	// Protocol Baselines
	ProtocolCoverage  map[string]float64 // Coverage by protocol
	ProtocolMaturity  map[string]float64 // Maturity of protocol baselines
	ProtocolStability map[string]float64 // Stability of protocol baselines

	// Data Quality
	DataCompleteness float64 // Measure of data completeness (0-1)
	DataConsistency  float64 // Consistency of incoming data (0-1)
	GapCount         int     // Number of gaps in baseline data
	DataQualityTrend float64 // Trend in data quality over time
}

// BaselineHealthStatus provides a simplified status assessment
type BaselineHealthStatus struct {
	Status         string    // Overall status (Learning/Stable/Degraded/Unhealthy)
	Score          float64   // Normalized health score (0-1)
	Issues         []string  // List of identified issues
	LastAssessment time.Time // Time of last health assessment

	// Component Status
	LearningStatus  string // Status of learning process
	CoverageStatus  string // Status of data coverage
	StabilityStatus string // Status of baseline stability
	QualityStatus   string // Status of data quality
}

// BaselineHealthThresholds defines acceptable ranges for health metrics
type BaselineHealthThresholds struct {
	MinConfidence  float64 // Minimum acceptable confidence
	MinStability   float64 // Minimum acceptable stability
	MinCoverage    float64 // Minimum acceptable coverage
	MinDataQuality float64 // Minimum acceptable data quality
	MaxDataAge     float64 // Maximum acceptable data age
	MinTimeWindows int     // Minimum number of time windows
}

// BaselineHealthConfig provides configuration for health monitoring
type BaselineHealthConfig struct {
	AssessmentInterval time.Duration // How often to assess health
	StabilityWindow    time.Duration // Window for stability calculations
	MinDataPoints      int           // Minimum data points for assessment
	CoverageWindows    []string      // Time windows to monitor
	Thresholds         BaselineHealthThresholds
}

// HealthAssessor defines the interface for health assessment
type HealthAssessor interface {
	AssessHealth() BaselineHealth
	GetStatus() BaselineHealthStatus
	IsHealthy() bool
	GetIssues() []string
	GetHealth() BaselineHealth
}

// Manager handles baseline learning and anomaly detection
type Manager struct {
	config Config
	mu     sync.RWMutex

	// Track learning state
	startTime     time.Time
	sampleCount   int
	isInitialized bool

	// Protocol-specific metrics
	protocolStats map[string]*ProtocolStats

	// Time-based patterns
	hourlyPatterns  map[int]*TimeWindowStats    // 0-23 hours
	dailyPatterns   map[time.Weekday]*TimeStats // Sunday-Saturday
	monthlyPatterns map[time.Month]*TimeStats   // Jan-Dec

	// Channels
	metricsChan chan capture.StatsSnapshot
	done        chan struct{}

	// Persistence
	lastCheckpoint time.Time

	// Health metrics
	health   *BaselineHealth
	healthMu sync.RWMutex
}

// persistedState represents the state to be saved/loaded
type persistedState struct {
	StartTime       time.Time
	SampleCount     int
	IsInitialized   bool
	ProtocolStats   map[string]*ProtocolStats
	HourlyPatterns  map[int]*TimeWindowStats
	DailyPatterns   map[time.Weekday]*TimeStats
	MonthlyPatterns map[time.Month]*TimeStats
	LastCheckpoint  time.Time
}

func init() {
	// Register types for gob encoding
	gob.Register(map[string]*ProtocolStats{})
	gob.Register(map[int]*TimeWindowStats{})
	gob.Register(map[time.Weekday]*TimeStats{})
	gob.Register(map[time.Month]*TimeStats{})
	gob.Register(&ProtocolStats{})
	gob.Register(&TimeWindowStats{})
	gob.Register(&TimeStats{})
	gob.Register([]uint64{})
	gob.Register([]time.Time{})
}

// validateState performs basic validation of loaded state
func validateState(state *persistedState) error {
	if state == nil {
		return fmt.Errorf("nil state")
	}

	// Validate maps are initialized
	if state.ProtocolStats == nil {
		return fmt.Errorf("nil protocol stats")
	}
	if state.HourlyPatterns == nil {
		return fmt.Errorf("nil hourly patterns")
	}
	if state.DailyPatterns == nil {
		return fmt.Errorf("nil daily patterns")
	}
	if state.MonthlyPatterns == nil {
		return fmt.Errorf("nil monthly patterns")
	}

	// Validate sample count
	if state.SampleCount < 0 {
		return fmt.Errorf("invalid sample count: %d", state.SampleCount)
	}

	// Validate timestamps
	if state.StartTime.IsZero() {
		return fmt.Errorf("invalid start time")
	}
	if state.LastCheckpoint.IsZero() {
		return fmt.Errorf("invalid last checkpoint time")
	}

	return nil
}

// Save persists the current state to disk
func (m *Manager) Save() error {
	if !m.config.PersistenceEnabled {
		return nil
	}

	// Create persistence directory with all parent directories
	if err := os.MkdirAll(m.config.PersistencePath, 0755); err != nil {
		return fmt.Errorf("failed to create persistence directory: %v", err)
	}

	// Verify directory exists and is writable
	if err := verifyDirectoryAccess(m.config.PersistencePath); err != nil {
		return fmt.Errorf("persistence directory access error: %v", err)
	}

	// Create a temporary file in the same directory
	tempFile := filepath.Join(m.config.PersistencePath, fmt.Sprintf("baseline.state.tmp.%d", time.Now().UnixNano()))
	file, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary state file: %v", err)
	}

	// Ensure cleanup of temporary file in case of errors
	removeTemp := true
	defer func() {
		file.Close()
		if removeTemp {
			os.Remove(tempFile)
		}
	}()

	// Take a snapshot of the state under lock
	m.mu.RLock()
	state := persistedState{
		StartTime:       m.startTime,
		SampleCount:     m.sampleCount,
		IsInitialized:   m.isInitialized,
		ProtocolStats:   m.protocolStats,
		HourlyPatterns:  m.hourlyPatterns,
		DailyPatterns:   m.dailyPatterns,
		MonthlyPatterns: m.monthlyPatterns,
		LastCheckpoint:  time.Now(),
	}
	m.mu.RUnlock()

	// Encode state
	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(state); err != nil {
		return fmt.Errorf("failed to encode state: %v", err)
	}

	// Ensure data is written to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync state file: %v", err)
	}

	// Close the file before renaming
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %v", err)
	}

	// Atomically rename temporary file
	finalPath := filepath.Join(m.config.PersistencePath, "baseline.state")
	if err := os.Rename(tempFile, finalPath); err != nil {
		return fmt.Errorf("failed to save state file: %v", err)
	}

	// Successfully renamed, don't remove the temp file
	removeTemp = false

	m.mu.Lock()
	m.lastCheckpoint = state.LastCheckpoint
	m.mu.Unlock()

	return nil
}

// verifyDirectoryAccess checks if a directory exists and is writable
func verifyDirectoryAccess(dir string) error {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat directory: %v", err)
	}

	// Check if it's a directory
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	// Check if directory is writable by attempting to create a temporary file
	testFile := filepath.Join(dir, fmt.Sprintf(".test.%d", time.Now().UnixNano()))
	f, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("directory is not writable: %v", err)
	}
	f.Close()
	os.Remove(testFile)

	return nil
}

// Load restores state from disk
func (m *Manager) Load() error {
	if !m.config.PersistenceEnabled {
		return nil
	}

	statePath := filepath.Join(m.config.PersistencePath, "baseline.state")
	file, err := os.OpenFile(statePath, os.O_RDONLY, 0600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No state file exists yet
		}
		return fmt.Errorf("failed to open state file: %v", err)
	}
	defer file.Close()

	// Read entire file content
	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read state file: %v", err)
	}

	// Decode state
	var state persistedState
	decoder := gob.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %v", err)
	}

	// Validate loaded state
	if err := validateState(&state); err != nil {
		return fmt.Errorf("invalid state loaded: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize maps if they don't exist
	if m.protocolStats == nil {
		m.protocolStats = make(map[string]*ProtocolStats)
	}
	if m.hourlyPatterns == nil {
		m.hourlyPatterns = make(map[int]*TimeWindowStats)
	}
	if m.dailyPatterns == nil {
		m.dailyPatterns = make(map[time.Weekday]*TimeStats)
	}
	if m.monthlyPatterns == nil {
		m.monthlyPatterns = make(map[time.Month]*TimeStats)
	}

	// Restore state
	m.startTime = state.StartTime
	m.sampleCount = state.SampleCount
	m.isInitialized = state.IsInitialized
	m.protocolStats = state.ProtocolStats
	m.hourlyPatterns = state.HourlyPatterns
	m.dailyPatterns = state.DailyPatterns
	m.monthlyPatterns = state.MonthlyPatterns
	m.lastCheckpoint = state.LastCheckpoint

	return nil
}

// ProtocolStats holds protocol-specific statistics
type ProtocolStats struct {
	// EWMA calculations for different time scales
	ShortTermVolume  *EWMA // 5-minute volume
	MediumTermVolume *EWMA // Hourly volume
	LongTermVolume   *EWMA // Daily volume

	// Byte-level metrics
	ShortTermBytes  *EWMA // 5-minute bytes
	MediumTermBytes *EWMA // Hourly bytes
	LongTermBytes   *EWMA // Daily bytes

	// Variance tracking
	PacketVariance *VarianceTracker // Packet count variance
	ByteVariance   *VarianceTracker // Byte count variance
	BurstVariance  *VarianceTracker // Burst size variance

	// Protocol-specific patterns
	ConnectionCount    *EWMA            // Active connection count
	AveragePacketSize  *EWMA            // Average packet size
	BurstDetection     *VarianceTracker // For detecting traffic bursts
	ConnectionDuration *EWMA            // Average connection duration

	// Historical data
	PacketCounts []uint64
	ByteCounts   []uint64
	Timestamps   []time.Time

	// Protocol-specific thresholds
	PacketThreshold float64 // Threshold for packet anomalies
	ByteThreshold   float64 // Threshold for byte anomalies
	BurstThreshold  float64 // Threshold for burst anomalies

	// Last update timestamp
	LastUpdated time.Time
}

// TimeWindowStats holds statistics for a specific time window
type TimeWindowStats struct {
	PacketCount *EWMA
	ByteCount   *EWMA
	Variance    *VarianceTracker
}

// TimeStats holds basic statistics for a time period
type TimeStats struct {
	AveragePackets float64
	AverageBytes   float64
	StdDevPackets  float64
	StdDevBytes    float64
	SampleCount    int
}

// NewManager creates a new baseline manager
func NewManager(config Config) (*Manager, error) {
	if config.InitialLearningPeriod <= 0 {
		return nil, fmt.Errorf("initial learning period must be positive")
	}
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("update interval must be positive")
	}
	if config.MinSamples <= 0 {
		return nil, fmt.Errorf("minimum samples must be positive")
	}

	m := &Manager{
		config:          config,
		startTime:       time.Now(),
		protocolStats:   make(map[string]*ProtocolStats),
		hourlyPatterns:  make(map[int]*TimeWindowStats),
		dailyPatterns:   make(map[time.Weekday]*TimeStats),
		monthlyPatterns: make(map[time.Month]*TimeStats),
		metricsChan:     make(chan capture.StatsSnapshot, 1000),
		done:            make(chan struct{}),
		health: &BaselineHealth{
			ProtocolCoverage:   make(map[string]float64),
			ProtocolMaturity:   make(map[string]float64),
			ProtocolStability:  make(map[string]float64),
			TimeWindowCoverage: make(map[string]float64),
			LastUpdate:         time.Now(),
		},
	}

	// Initialize hourly patterns
	for hour := 0; hour < 24; hour++ {
		m.hourlyPatterns[hour] = &TimeWindowStats{
			PacketCount: NewEWMA(config.MediumTermAlpha),
			ByteCount:   NewEWMA(config.MediumTermAlpha),
			Variance:    NewVarianceTracker(),
		}
	}

	// Initialize daily patterns
	for day := time.Sunday; day <= time.Saturday; day++ {
		m.dailyPatterns[day] = &TimeStats{}
	}

	// Initialize monthly patterns
	for month := time.January; month <= time.December; month++ {
		m.monthlyPatterns[month] = &TimeStats{}
	}

	return m, nil
}

// Start begins the baseline learning process
func (m *Manager) Start(ctx context.Context) error {
	// Try to load existing state
	if err := m.Load(); err != nil {
		return fmt.Errorf("failed to load state: %v", err)
	}

	go m.run(ctx)
	return nil
}

// Stop stops the baseline learning process
func (m *Manager) Stop() error {
	close(m.done)
	return nil
}

// AddMetrics adds a new metrics snapshot for baseline learning
func (m *Manager) AddMetrics(snapshot capture.StatsSnapshot) {
	select {
	case m.metricsChan <- snapshot:
	default:
		// Channel full, skip this update
	}
}

// run is the main processing loop
func (m *Manager) run(ctx context.Context) {
	ticker := time.NewTicker(m.config.UpdateInterval)
	var checkpointTicker *time.Ticker
	if m.config.PersistenceEnabled {
		checkpointTicker = time.NewTicker(m.config.CheckpointInterval)
	}
	healthTicker := time.NewTicker(time.Minute) // Update health metrics every minute
	defer ticker.Stop()
	if checkpointTicker != nil {
		defer checkpointTicker.Stop()
	}
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Save state before shutting down
			if err := m.Save(); err != nil {
				log.Printf("Failed to save state on shutdown: %v", err)
			}
			return
		case <-m.done:
			if err := m.Save(); err != nil {
				log.Printf("Failed to save state on shutdown: %v", err)
			}
			return
		case snapshot := <-m.metricsChan:
			m.processSnapshot(snapshot)
		case <-ticker.C:
			m.updateBaselines()
		case <-checkpointTicker.C:
			if err := m.Save(); err != nil {
				log.Printf("Failed to save checkpoint: %v", err)
			}
		case <-healthTicker.C:
			m.UpdateHealth()
		}
	}
}

// processSnapshot processes a new metrics snapshot
func (m *Manager) processSnapshot(snapshot capture.StatsSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sampleCount++

	// Process each protocol
	for proto, packetCount := range snapshot.PacketsByProtocol {
		stats := m.getOrCreateProtocolStats(proto)
		byteCount := snapshot.BytesByProtocol[proto]

		// Update all protocol-specific stats
		stats.UpdateStats(packetCount, byteCount, snapshot.LastUpdated)

		// Check for anomalies if initialized
		if m.isInitialized {
			if stats.IsAnomaly(packetCount, byteCount) {
				log.Printf("Anomaly detected for protocol %s: packets=%d, bytes=%d",
					proto, packetCount, byteCount)
			}
		}
	}

	// Update time-based patterns
	hour := snapshot.LastUpdated.Hour()
	if hourStats, ok := m.hourlyPatterns[hour]; ok {
		hourStats.PacketCount.Update(float64(snapshot.TotalPackets))
		hourStats.ByteCount.Update(float64(snapshot.TotalBytes))
		hourStats.Variance.Add(float64(snapshot.TotalPackets))
	}
}

// updateBaselines updates all baseline calculations
func (m *Manager) updateBaselines() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we've completed initial learning
	if !m.isInitialized && m.sampleCount >= m.config.MinSamples {
		m.isInitialized = true
	}

	// Update time-based patterns
	m.updateTimePatterns()
}

// updateTimePatterns updates the time-based pattern statistics
func (m *Manager) updateTimePatterns() {
	// Process daily patterns
	for day := time.Sunday; day <= time.Saturday; day++ {
		stats := m.dailyPatterns[day]
		if hourStats, ok := m.hourlyPatterns[int(day)]; ok {
			packetRate := hourStats.PacketCount.GetValue()
			byteRate := hourStats.ByteCount.GetValue()
			variance := hourStats.Variance.GetVariance()
			stats.AveragePackets = packetRate
			stats.AverageBytes = byteRate
			stats.StdDevPackets = math.Sqrt(variance)
			stats.SampleCount++
		}
	}

	// Process monthly patterns
	now := time.Now()
	if monthStats, ok := m.monthlyPatterns[now.Month()]; ok {
		var totalPackets, totalBytes float64
		var packetSamples, byteSamples []float64

		// Collect data from all hours in the current month
		for hour := 0; hour < 24; hour++ {
			if hourStats, ok := m.hourlyPatterns[hour]; ok {
				packetRate := hourStats.PacketCount.GetValue()
				byteRate := hourStats.ByteCount.GetValue()
				totalPackets += packetRate
				totalBytes += byteRate
				packetSamples = append(packetSamples, packetRate)
				byteSamples = append(byteSamples, byteRate)
			}
		}

		// Update monthly statistics
		if len(packetSamples) > 0 {
			monthStats.AveragePackets = totalPackets / float64(len(packetSamples))
			monthStats.AverageBytes = totalBytes / float64(len(byteSamples))
			monthStats.SampleCount = len(packetSamples)

			// Calculate standard deviations
			var packetSumSq, byteSumSq float64
			for i := 0; i < len(packetSamples); i++ {
				diff := packetSamples[i] - monthStats.AveragePackets
				packetSumSq += diff * diff
				diff = byteSamples[i] - monthStats.AverageBytes
				byteSumSq += diff * diff
			}
			monthStats.StdDevPackets = math.Sqrt(packetSumSq / float64(len(packetSamples)))
			monthStats.StdDevBytes = math.Sqrt(byteSumSq / float64(len(byteSamples)))
		}
	}

	// Update hourly patterns with adaptive thresholds
	for hour := 0; hour < 24; hour++ {
		if hourStats, ok := m.hourlyPatterns[hour]; ok {
			// Get current hour's stats
			packetRate := hourStats.PacketCount.GetValue()
			byteRate := hourStats.ByteCount.GetValue()

			// Adjust thresholds based on time of day
			isBusinessHour := hour >= 9 && hour <= 17
			if isBusinessHour {
				// During business hours, use tighter thresholds
				hourStats.Variance.Add(packetRate * 0.8) // More weight on current values
			} else {
				// During off hours, use looser thresholds
				hourStats.Variance.Add(packetRate * 1.2) // More tolerance for variation
			}

			// Update EWMA with current rates
			hourStats.PacketCount.Update(packetRate)
			hourStats.ByteCount.Update(byteRate)
		}
	}
}

// getOrCreateProtocolStats gets or creates protocol-specific stats
func (m *Manager) getOrCreateProtocolStats(protocol string) *ProtocolStats {
	stats, ok := m.protocolStats[protocol]
	if !ok {
		stats = NewProtocolStats(m.config)
		m.protocolStats[protocol] = stats
	}
	return stats
}

// IsInitialized returns whether the baseline has completed initial learning
func (m *Manager) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isInitialized
}

// GetProtocolStats returns statistics for a specific protocol
func (m *Manager) GetProtocolStats(protocol string) (*ProtocolStats, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats, ok := m.protocolStats[protocol]
	return stats, ok
}

// NewProtocolStats creates a new ProtocolStats instance
func NewProtocolStats(config Config) *ProtocolStats {
	return &ProtocolStats{
		// Volume tracking
		ShortTermVolume:  NewEWMA(config.ShortTermAlpha),
		MediumTermVolume: NewEWMA(config.MediumTermAlpha),
		LongTermVolume:   NewEWMA(config.LongTermAlpha),

		// Byte tracking
		ShortTermBytes:  NewEWMA(config.ShortTermAlpha),
		MediumTermBytes: NewEWMA(config.MediumTermAlpha),
		LongTermBytes:   NewEWMA(config.LongTermAlpha),

		// Variance tracking
		PacketVariance: NewVarianceTracker(),
		ByteVariance:   NewVarianceTracker(),
		BurstVariance:  NewVarianceTracker(),

		// Protocol patterns
		ConnectionCount:    NewEWMA(config.ShortTermAlpha),
		AveragePacketSize:  NewEWMA(config.MediumTermAlpha),
		BurstDetection:     NewVarianceTracker(),
		ConnectionDuration: NewEWMA(config.MediumTermAlpha),

		// Historical data
		PacketCounts: make([]uint64, 0),
		ByteCounts:   make([]uint64, 0),
		Timestamps:   make([]time.Time, 0),

		// Default thresholds
		PacketThreshold: config.AnomalyThreshold,
		ByteThreshold:   config.AnomalyThreshold,
		BurstThreshold:  config.AnomalyThreshold,

		LastUpdated: time.Now(),
	}
}

// UpdateStats updates all statistics for the protocol
func (ps *ProtocolStats) UpdateStats(packets, bytes uint64, timestamp time.Time) {
	// Update volume metrics
	ps.ShortTermVolume.Update(float64(packets))
	ps.MediumTermVolume.Update(float64(packets))
	ps.LongTermVolume.Update(float64(packets))

	// Update byte metrics
	ps.ShortTermBytes.Update(float64(bytes))
	ps.MediumTermBytes.Update(float64(bytes))
	ps.LongTermBytes.Update(float64(bytes))

	// Update variance trackers
	ps.PacketVariance.Add(float64(packets))
	ps.ByteVariance.Add(float64(bytes))

	// Calculate and update average packet size
	if packets > 0 {
		avgPacketSize := float64(bytes) / float64(packets)
		ps.AveragePacketSize.Update(avgPacketSize)
	}

	// Update historical data
	ps.PacketCounts = append(ps.PacketCounts, packets)
	ps.ByteCounts = append(ps.ByteCounts, bytes)
	ps.Timestamps = append(ps.Timestamps, timestamp)

	// Update timestamp
	ps.LastUpdated = timestamp
}

// IsAnomaly checks if current metrics indicate an anomaly
func (ps *ProtocolStats) IsAnomaly(packets, bytes uint64) bool {
	// Check packet count anomaly
	if ps.PacketVariance.IsAnomaly(float64(packets), ps.PacketThreshold) {
		return true
	}

	// Check byte count anomaly
	if ps.ByteVariance.IsAnomaly(float64(bytes), ps.ByteThreshold) {
		return true
	}

	// Check for burst anomaly
	if ps.BurstVariance.IsAnomaly(float64(packets), ps.BurstThreshold) {
		return true
	}

	return false
}

// GetStats returns current statistics for the protocol
func (ps *ProtocolStats) GetStats() map[string]float64 {
	return map[string]float64{
		"short_term_volume":  ps.ShortTermVolume.GetValue(),
		"medium_term_volume": ps.MediumTermVolume.GetValue(),
		"long_term_volume":   ps.LongTermVolume.GetValue(),
		"short_term_bytes":   ps.ShortTermBytes.GetValue(),
		"medium_term_bytes":  ps.MediumTermBytes.GetValue(),
		"long_term_bytes":    ps.LongTermBytes.GetValue(),
		"avg_packet_size":    ps.AveragePacketSize.GetValue(),
		"packet_variance":    ps.PacketVariance.GetVariance(),
		"byte_variance":      ps.ByteVariance.GetVariance(),
	}
}

// UpdateHealth updates baseline health metrics
func (m *Manager) UpdateHealth() {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()

	now := time.Now()

	// Calculate learning progress and phase
	progress := float64(m.sampleCount) / float64(m.config.MinSamples)
	if progress > 1.0 {
		progress = 1.0
	}

	// Determine learning phase
	var learningPhase string
	switch {
	case progress < 0.3:
		learningPhase = "Initial"
	case progress < 1.0:
		learningPhase = "Active"
	default:
		learningPhase = "Stable"
	}

	// Calculate baseline quality metrics
	stability := m.calculateStability()
	coverage := m.calculateCoverage()
	maturity := m.calculateMaturity()

	// Calculate statistical health
	meanStability := m.calculateMeanStability()
	varianceStability := m.calculateVarianceStability()
	distributionQuality := m.calculateDistributionQuality()
	stationarityScore := m.calculateStationarityScore()

	// Calculate temporal coverage
	timeWindowCoverage := m.calculateTimeWindowCoverage()
	temporalStability := m.calculateTemporalStability()
	seasonalityScore := m.calculateSeasonalityScore()
	dataFreshness := m.calculateDataFreshness()

	// Calculate protocol metrics
	protocolCoverage := m.calculateProtocolCoverage()
	protocolMaturity := m.calculateProtocolMaturity()
	protocolStability := m.calculateProtocolStability()

	// Calculate data quality metrics
	dataCompleteness := m.calculateDataCompleteness()
	dataConsistency := m.calculateDataConsistency()
	gapCount := m.calculateGapCount()
	dataQualityTrend := m.calculateDataQualityTrend()

	// Update health metrics
	m.health.LearningProgress = progress * 100
	m.health.LearningPhase = learningPhase
	m.health.DataPoints = m.sampleCount
	m.health.LastUpdate = now

	m.health.Confidence = (stability + coverage + maturity) / 3.0
	m.health.Stability = stability
	m.health.Coverage = coverage
	m.health.Maturity = maturity

	m.health.MeanStability = meanStability
	m.health.VarianceStability = varianceStability
	m.health.DistributionQuality = distributionQuality
	m.health.StationarityScore = stationarityScore

	m.health.TimeWindowCoverage = timeWindowCoverage
	m.health.TemporalStability = temporalStability
	m.health.SeasonalityScore = seasonalityScore
	m.health.DataFreshness = dataFreshness

	m.health.ProtocolCoverage = protocolCoverage
	m.health.ProtocolMaturity = protocolMaturity
	m.health.ProtocolStability = protocolStability

	m.health.DataCompleteness = dataCompleteness
	m.health.DataConsistency = dataConsistency
	m.health.GapCount = gapCount
	m.health.DataQualityTrend = dataQualityTrend
}

// GetHealthStatus returns the current health status
func (m *Manager) GetHealthStatus() BaselineHealthStatus {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()

	health := m.health
	status := BaselineHealthStatus{
		LastAssessment: time.Now(),
		Issues:         make([]string, 0),
	}

	// Determine component status
	status.LearningStatus = health.LearningPhase
	status.CoverageStatus = m.determineCoverageStatus()
	status.StabilityStatus = m.determineStabilityStatus()
	status.QualityStatus = m.determineQualityStatus()

	// Calculate overall score
	status.Score = m.calculateOverallScore()

	// Determine overall status
	status.Status = m.determineOverallStatus(status.Score)

	// Identify issues
	status.Issues = m.identifyIssues()

	return status
}

// IsHealthy returns whether the baseline is considered healthy
func (m *Manager) IsHealthy() bool {
	status := m.GetHealthStatus()
	return status.Status == "Stable" || status.Status == "Learning"
}

// GetIssues returns the current list of health issues
func (m *Manager) GetIssues() []string {
	return m.GetHealthStatus().Issues
}

// Helper functions for health calculations

func (m *Manager) calculateMaturity() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.sampleCount == 0 {
		return 0
	}

	// Consider multiple factors for maturity
	learningProgress := float64(m.sampleCount) / float64(m.config.MinSamples)
	timeProgress := time.Since(m.startTime).Hours() / m.config.InitialLearningPeriod.Hours()
	stability := m.calculateStability()

	// Combine factors with weights
	maturity := (learningProgress*0.4 + timeProgress*0.3 + stability*0.3)
	return math.Min(maturity, 1.0)
}

func (m *Manager) calculateMeanStability() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalStability float64
	var count int

	for _, stats := range m.protocolStats {
		if stats.ShortTermVolume.GetCount() > 0 {
			// Calculate stability of mean values over time
			meanDiff := math.Abs(stats.ShortTermVolume.GetValue() - stats.LongTermVolume.GetValue())
			meanValue := stats.LongTermVolume.GetValue()
			if meanValue > 0 {
				stability := 1.0 / (1.0 + meanDiff/meanValue)
				totalStability += stability
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalStability / float64(count)
}

func (m *Manager) calculateVarianceStability() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalStability float64
	var count int

	for _, stats := range m.protocolStats {
		if stats.PacketVariance.GetCount() > 0 {
			// Calculate stability of variance over time
			variance := stats.PacketVariance.GetVariance()
			if variance > 0 {
				stability := 1.0 / (1.0 + math.Log1p(variance))
				totalStability += stability
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalStability / float64(count)
}

func (m *Manager) calculateDistributionQuality() float64 {
	// Implement distribution quality calculation
	// This could involve checking for normality, skewness, kurtosis, etc.
	return 0.0 // Placeholder
}

func (m *Manager) calculateStationarityScore() float64 {
	// Implement stationarity calculation
	// This could involve statistical tests for stationarity
	return 0.0 // Placeholder
}

func (m *Manager) calculateTimeWindowCoverage() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	coverage := make(map[string]float64)

	// Calculate hourly coverage
	activeHours := 0
	for _, stats := range m.hourlyPatterns {
		if stats.PacketCount.GetCount() > 0 {
			activeHours++
		}
	}
	coverage["hourly"] = float64(activeHours) / 24.0

	// Calculate daily coverage
	activeDays := 0
	for _, stats := range m.dailyPatterns {
		if stats.SampleCount > 0 {
			activeDays++
		}
	}
	coverage["daily"] = float64(activeDays) / 7.0

	// Calculate monthly coverage
	activeMonths := 0
	for _, stats := range m.monthlyPatterns {
		if stats.SampleCount > 0 {
			activeMonths++
		}
	}
	coverage["monthly"] = float64(activeMonths) / 12.0

	return coverage
}

func (m *Manager) calculateTemporalStability() float64 {
	// Calculate stability across different time windows
	hourlyStability := m.calculateHourlyStability()
	dailyStability := m.calculateDailyStability()
	monthlyStability := m.calculateMonthlyStability()

	return (hourlyStability + dailyStability + monthlyStability) / 3.0
}

func (m *Manager) calculateSeasonalityScore() float64 {
	// Implement seasonality detection quality calculation
	return 0.0 // Placeholder
}

func (m *Manager) calculateDataFreshness() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var latestUpdate time.Time
	for _, stats := range m.protocolStats {
		if stats.LastUpdated.After(latestUpdate) {
			latestUpdate = stats.LastUpdated
		}
	}

	if latestUpdate.IsZero() {
		return 0
	}

	// Convert age to a score between 0 and 1
	age := time.Since(latestUpdate)
	maxAge := m.config.UpdateInterval * 2
	freshness := 1.0 - (age.Seconds() / maxAge.Seconds())
	return math.Max(0, math.Min(1, freshness))
}

func (m *Manager) calculateProtocolMaturity() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	maturity := make(map[string]float64)
	for proto, stats := range m.protocolStats {
		if stats.ShortTermVolume.GetCount() > 0 {
			// Calculate maturity based on sample count and stability
			sampleProgress := float64(stats.ShortTermVolume.GetCount()) / float64(m.config.MinSamples)
			stability := 1.0 / (1.0 + math.Sqrt(stats.PacketVariance.GetVariance()))
			maturity[proto] = math.Min(1.0, (sampleProgress*0.7 + stability*0.3))
		}
	}
	return maturity
}

func (m *Manager) calculateProtocolStability() map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stability := make(map[string]float64)
	for proto, stats := range m.protocolStats {
		if stats.ShortTermVolume.GetCount() > 0 {
			cv := math.Sqrt(stats.PacketVariance.GetVariance()) / stats.ShortTermVolume.GetValue()
			stability[proto] = 1.0 / (1.0 + cv)
		}
	}
	return stability
}

func (m *Manager) calculateDataCompleteness() float64 {
	// Calculate data completeness based on expected vs actual data points
	expectedPoints := int(time.Since(m.startTime) / m.config.UpdateInterval)
	if expectedPoints == 0 {
		return 1.0
	}
	return math.Min(1.0, float64(m.sampleCount)/float64(expectedPoints))
}

func (m *Manager) calculateDataConsistency() float64 {
	// Implement data consistency calculation
	return 0.0 // Placeholder
}

func (m *Manager) calculateGapCount() int {
	// Implement gap detection
	return 0 // Placeholder
}

func (m *Manager) calculateDataQualityTrend() float64 {
	// Implement data quality trend calculation
	return 0.0 // Placeholder
}

func (m *Manager) calculateOverallScore() float64 {
	health := m.health

	// Weight different components
	learningWeight := 0.2
	qualityWeight := 0.3
	stabilityWeight := 0.3
	coverageWeight := 0.2

	score := (health.LearningProgress/100.0)*learningWeight +
		health.Confidence*qualityWeight +
		health.Stability*stabilityWeight +
		health.Coverage*coverageWeight

	return score
}

func (m *Manager) determineOverallStatus(score float64) string {
	health := m.health

	if health.LearningProgress < 100 {
		return "Learning"
	}

	switch {
	case score >= 0.8:
		return "Stable"
	case score >= 0.6:
		return "Degraded"
	default:
		return "Unhealthy"
	}
}

func (m *Manager) determineCoverageStatus() string {
	coverage := m.health.Coverage
	switch {
	case coverage >= 0.8:
		return "Good"
	case coverage >= 0.5:
		return "Partial"
	default:
		return "Insufficient"
	}
}

func (m *Manager) determineStabilityStatus() string {
	stability := m.health.Stability
	switch {
	case stability >= 0.8:
		return "Stable"
	case stability >= 0.5:
		return "Variable"
	default:
		return "Unstable"
	}
}

func (m *Manager) determineQualityStatus() string {
	quality := m.health.DataCompleteness * m.health.DataConsistency
	switch {
	case quality >= 0.8:
		return "Good"
	case quality >= 0.5:
		return "Fair"
	default:
		return "Poor"
	}
}

func (m *Manager) identifyIssues() []string {
	var issues []string
	health := m.health

	// Check learning progress
	if health.LearningProgress < 100 {
		issues = append(issues, fmt.Sprintf("Still learning: %.1f%% complete", health.LearningProgress))
	}

	// Check coverage
	if health.Coverage < 0.8 {
		issues = append(issues, fmt.Sprintf("Insufficient coverage: %.1f%%", health.Coverage*100))
	}

	// Check stability
	if health.Stability < 0.7 {
		issues = append(issues, fmt.Sprintf("Low stability: %.1f%%", health.Stability*100))
	}

	// Check data quality
	if health.DataCompleteness < 0.8 {
		issues = append(issues, fmt.Sprintf("Data completeness issues: %.1f%%", health.DataCompleteness*100))
	}

	// Check data freshness
	if health.DataFreshness < 0.8 {
		issues = append(issues, "Data freshness below threshold")
	}

	return issues
}

// calculateStability computes the stability score based on variance
func (m *Manager) calculateStability() float64 {
	var totalStability float64
	var count int

	for _, stats := range m.protocolStats {
		if stats.ShortTermVolume.GetCount() > 0 {
			// Calculate coefficient of variation
			stdDev := math.Sqrt(stats.PacketVariance.GetVariance())
			mean := stats.ShortTermVolume.GetValue()
			if mean > 0 {
				cv := stdDev / mean
				// Convert to stability score (lower CV = higher stability)
				stability := 1.0 / (1.0 + cv)
				totalStability += stability
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalStability / float64(count)
}

// calculateCoverage computes the data coverage score
func (m *Manager) calculateCoverage() float64 {
	var coverage float64
	totalWindows := 24 // hourly windows
	activeWindows := 0

	for _, window := range m.hourlyPatterns {
		if window.PacketCount.GetCount() > 0 {
			activeWindows++
		}
	}

	coverage = float64(activeWindows) / float64(totalWindows)
	return coverage
}

// calculateProtocolCoverage computes coverage metrics for each protocol
func (m *Manager) calculateProtocolCoverage() map[string]float64 {
	coverage := make(map[string]float64)
	for proto, stats := range m.protocolStats {
		if stats.ShortTermVolume.GetCount() > 0 {
			coverage[proto] = float64(stats.ShortTermVolume.GetCount()) / float64(m.sampleCount)
		}
	}
	return coverage
}

// calculateHourlyStability computes stability across hourly patterns
func (m *Manager) calculateHourlyStability() float64 {
	var totalStability float64
	var count int

	for _, stats := range m.hourlyPatterns {
		if stats.PacketCount.GetCount() > 0 {
			variance := stats.Variance.GetVariance()
			if variance > 0 {
				stability := 1.0 / (1.0 + math.Log1p(variance))
				totalStability += stability
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalStability / float64(count)
}

// calculateDailyStability computes stability across daily patterns
func (m *Manager) calculateDailyStability() float64 {
	var totalStability float64
	var count int

	for _, stats := range m.dailyPatterns {
		if stats.SampleCount > 0 {
			// Use coefficient of variation as stability measure
			if stats.AveragePackets > 0 {
				cv := stats.StdDevPackets / stats.AveragePackets
				stability := 1.0 / (1.0 + cv)
				totalStability += stability
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalStability / float64(count)
}

// calculateMonthlyStability computes stability across monthly patterns
func (m *Manager) calculateMonthlyStability() float64 {
	var totalStability float64
	var count int

	for _, stats := range m.monthlyPatterns {
		if stats.SampleCount > 0 {
			// Use coefficient of variation as stability measure
			if stats.AveragePackets > 0 {
				cv := stats.StdDevPackets / stats.AveragePackets
				stability := 1.0 / (1.0 + cv)
				totalStability += stability
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalStability / float64(count)
}

// GetHealth returns the current baseline health metrics
func (m *Manager) GetHealth() BaselineHealth {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()
	return *m.health
}
