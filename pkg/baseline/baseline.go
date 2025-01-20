package baseline

import (
	"context"
	"encoding/gob"
	"fmt"
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

// Save persists the current state to disk
func (m *Manager) Save() error {
	if !m.config.PersistenceEnabled {
		return nil
	}

	// Create persistence directory if it doesn't exist
	if err := os.MkdirAll(m.config.PersistencePath, 0755); err != nil {
		return fmt.Errorf("failed to create persistence directory: %v", err)
	}

	// Create a temporary file for atomic write
	tempFile := filepath.Join(m.config.PersistencePath, "baseline.state.tmp")
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary state file: %v", err)
	}
	defer file.Close()

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

	// Atomically rename temporary file
	finalPath := filepath.Join(m.config.PersistencePath, "baseline.state")
	if err := os.Rename(tempFile, finalPath); err != nil {
		return fmt.Errorf("failed to save state file: %v", err)
	}

	m.mu.Lock()
	m.lastCheckpoint = state.LastCheckpoint
	m.mu.Unlock()

	return nil
}

// Load restores state from disk
func (m *Manager) Load() error {
	if !m.config.PersistenceEnabled {
		return nil
	}

	statePath := filepath.Join(m.config.PersistencePath, "baseline.state")
	file, err := os.Open(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No state file exists yet
		}
		return fmt.Errorf("failed to open state file: %v", err)
	}
	defer file.Close()

	var state persistedState
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %v", err)
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
	defer ticker.Stop()
	if checkpointTicker != nil {
		defer checkpointTicker.Stop()
	}

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
