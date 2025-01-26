package baseline

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

func init() {
	// Register types for gob encoding
	gob.Register(&MultiDimBaseline{})
	gob.Register(&DimensionStats{})
	gob.Register(&MultiDimPoint{})
	gob.Register([]MultiDimPoint{})
	gob.Register(&SeasonalityDetector{})
	gob.Register(&SeasonalPattern{})
	gob.Register(map[string]*SeasonalPattern{})
	gob.Register(map[string]*DimensionStats{})
	gob.Register(map[string]*CorrelationTracker{})
	gob.Register(&CorrelationTracker{})
	gob.Register(&VarianceTracker{})
	gob.Register(&EWMA{})
	gob.Register(map[string][]time.Time{})
	gob.Register(DimensionHistory{})
	gob.Register(map[string]time.Time{})
	gob.Register(&multiDimState{})
	gob.Register(struct {
		Coverage    float64
		Stability   float64
		LastUpdate  time.Time
		DataQuality float64
	}{})
	gob.Register(struct {
		MinDataPoints  int
		MaxDataPoints  int
		WindowSize     time.Duration
		UpdateInterval time.Duration
	}{})
}

// MultiDimPoint represents a point in multi-dimensional space
type MultiDimPoint struct {
	Values    map[string]float64 // Dimension name -> value
	Timestamp time.Time
}

// DimensionStats tracks statistics for a single dimension
type DimensionStats struct {
	Name      string
	Variance  *VarianceTracker
	EWMA      *EWMA
	Weight    float64   // Importance weight for this dimension
	Bounds    []float64 // Historical bounds for anomaly detection
	LastValue float64
}

// DimensionHistory tracks when each dimension was last seen
type DimensionHistory struct {
	LastSeen map[string]time.Time
}

// MultiDimBaseline implements multi-dimensional baseline modeling
type MultiDimBaseline struct {
	mu sync.RWMutex

	// Core components
	Dimensions    map[string]*DimensionStats
	Points        []MultiDimPoint
	MaxPoints     int
	UpdateCounter int

	// Correlation tracking
	DimensionCorrelations map[string]*CorrelationTracker // Maps "dim1:dim2" to correlation

	// Seasonality detection
	SeasonalityDetector *SeasonalityDetector

	// Configuration
	Config struct {
		MinDataPoints  int
		MaxDataPoints  int
		WindowSize     time.Duration
		UpdateInterval time.Duration
	}

	// Quality metrics
	Quality struct {
		Coverage    float64 // 0-1 score for data coverage
		Stability   float64 // 0-1 score for baseline stability
		LastUpdate  time.Time
		DataQuality float64 // 0-1 score for data quality
	}

	// Track dimension history
	DimensionHistory map[string][]time.Time
	history          DimensionHistory
}

// NewMultiDimBaseline creates a new multi-dimensional baseline
func NewMultiDimBaseline(dimensions []string, config Config) (*MultiDimBaseline, error) {
	if len(dimensions) == 0 {
		return nil, fmt.Errorf("at least one dimension required")
	}

	mdb := &MultiDimBaseline{
		Dimensions:            make(map[string]*DimensionStats),
		DimensionCorrelations: make(map[string]*CorrelationTracker),
		Points:                make([]MultiDimPoint, 0),
		MaxPoints:             10000, // Default max points
		DimensionHistory:      make(map[string][]time.Time),
		history: DimensionHistory{
			LastSeen: make(map[string]time.Time),
		},
	}

	// Initialize dimensions with equal weights
	weight := 1.0 / float64(len(dimensions))
	for _, dim := range dimensions {
		mdb.Dimensions[dim] = &DimensionStats{
			Name:     dim,
			Variance: NewVarianceTracker(),
			EWMA:     NewEWMA(config.MediumTermAlpha),
			Weight:   weight,
			Bounds:   make([]float64, 0),
		}
	}

	// Initialize correlation trackers for all dimension pairs
	for i := 0; i < len(dimensions); i++ {
		for j := i + 1; j < len(dimensions); j++ {
			dim1, dim2 := dimensions[i], dimensions[j]
			if dim2 < dim1 {
				dim1, dim2 = dim2, dim1
			}
			key := fmt.Sprintf("%s:%s", dim1, dim2)
			mdb.DimensionCorrelations[key] = NewCorrelationTracker()
		}
	}

	// Initialize seasonality detector
	mdb.SeasonalityDetector = NewSeasonalityDetector(config.UpdateInterval)

	// Initialize configuration
	mdb.Config.MinDataPoints = config.MinSamples
	mdb.Config.MaxDataPoints = 10000
	mdb.Config.WindowSize = 24 * time.Hour
	mdb.Config.UpdateInterval = config.UpdateInterval

	// Initialize quality metrics with minimum values
	mdb.Quality.Coverage = 0.1    // Start with minimal coverage
	mdb.Quality.Stability = 0.1   // Start with minimal stability
	mdb.Quality.DataQuality = 0.1 // Start with minimal quality
	mdb.Quality.LastUpdate = time.Now()

	return mdb, nil
}

// AddPoint adds a new multi-dimensional data point
func (mdb *MultiDimBaseline) AddPoint(point MultiDimPoint) error {
	mdb.mu.Lock()
	defer mdb.mu.Unlock()

	// Validate point dimensions
	for dim := range point.Values {
		if _, exists := mdb.Dimensions[dim]; !exists {
			return fmt.Errorf("unknown dimension: %s", dim)
		}
	}

	// Update dimension history
	for dim := range point.Values {
		mdb.history.LastSeen[dim] = point.Timestamp
	}

	// Update individual dimension statistics
	for dim, value := range point.Values {
		stats := mdb.Dimensions[dim]
		stats.Variance.Add(value)
		stats.EWMA.Update(value)
		stats.LastValue = value

		// Update seasonality detection
		mdb.SeasonalityDetector.AddValue(dim, value, point.Timestamp)
	}

	// Update correlations between dimensions
	dimensions := make([]string, 0, len(point.Values))
	for dim := range point.Values {
		dimensions = append(dimensions, dim)
	}

	// Sort dimensions to ensure consistent key generation
	sort.Strings(dimensions)

	// Update correlations for all dimension pairs
	for i := 0; i < len(dimensions); i++ {
		for j := i + 1; j < len(dimensions); j++ {
			dim1, dim2 := dimensions[i], dimensions[j]
			key := fmt.Sprintf("%s:%s", dim1, dim2)

			if corr, exists := mdb.DimensionCorrelations[key]; exists {
				val1 := point.Values[dim1]
				val2 := point.Values[dim2]
				corr.Add(val1, val2)
			}
		}
	}

	// Store point for historical analysis
	mdb.Points = append(mdb.Points, point)
	if len(mdb.Points) > mdb.MaxPoints {
		mdb.Points = mdb.Points[1:]
	}

	mdb.UpdateCounter++

	// Update quality metrics periodically
	if mdb.UpdateCounter%100 == 0 || len(mdb.Points) <= 10 {
		mdb.updateQualityMetrics()
	}

	return nil
}

// IsAnomaly checks if a point is anomalous in the multi-dimensional space
func (mdb *MultiDimBaseline) IsAnomaly(point MultiDimPoint) (bool, map[string]float64) {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	scores := make(map[string]float64)
	weightedScore := 0.0
	totalWeight := 0.0

	// Check each dimension
	for dim, value := range point.Values {
		stats := mdb.Dimensions[dim]

		// Calculate z-score
		zScore := math.Abs(stats.Variance.GetZScore(value))

		// Check seasonal pattern
		seasonalScore := mdb.SeasonalityDetector.GetSeasonalScore(dim, value, point.Timestamp)

		// Combine scores with seasonal adjustment
		combinedScore := zScore * (1.0 + (1.0 - seasonalScore))

		scores[dim] = combinedScore
		weightedScore += combinedScore * stats.Weight
		totalWeight += stats.Weight
	}

	// Calculate final anomaly score
	if totalWeight > 0 {
		weightedScore /= totalWeight
	}

	// Check correlation violations
	correlationPenalty := mdb.checkCorrelationViolations(point)
	weightedScore *= (1.0 + correlationPenalty)

	return weightedScore > 3.0, scores // Using 3.0 as default threshold (3 sigma rule)
}

// checkCorrelationViolations checks if the point violates established correlations
func (mdb *MultiDimBaseline) checkCorrelationViolations(point MultiDimPoint) float64 {
	maxViolation := 0.0

	for dim1, val1 := range point.Values {
		for dim2, val2 := range point.Values {
			if dim1 < dim2 {
				key := fmt.Sprintf("%s:%s", dim1, dim2)
				if corr, exists := mdb.DimensionCorrelations[key]; exists {
					expectedCorr := corr.GetCorrelation()
					if math.Abs(expectedCorr) > 0.8 { // Strong correlation threshold
						// Calculate actual correlation for this point
						actualCorr := mdb.calculatePointCorrelation(val1, val2)
						violation := math.Abs(expectedCorr - actualCorr)
						if violation > maxViolation {
							maxViolation = violation
						}
					}
				}
			}
		}
	}

	return maxViolation
}

// calculatePointCorrelation calculates correlation for a single point
func (mdb *MultiDimBaseline) calculatePointCorrelation(val1, val2 float64) float64 {
	// Simplified point correlation using normalized values
	norm1 := mdb.normalizeValue(val1)
	norm2 := mdb.normalizeValue(val2)
	return 1.0 - math.Abs(norm1-norm2)
}

// normalizeValue normalizes a value to [0,1] range
func (mdb *MultiDimBaseline) normalizeValue(value float64) float64 {
	return 1.0 / (1.0 + math.Exp(-value)) // Sigmoid normalization
}

// updateQualityMetrics updates the quality metrics for the baseline
func (mdb *MultiDimBaseline) updateQualityMetrics() {
	// Get all configured dimensions
	allDims := mdb.Dimensions
	if len(allDims) == 0 || len(mdb.Points) == 0 {
		mdb.Quality.Coverage = 0.1
		mdb.Quality.Stability = 0.1
		mdb.Quality.DataQuality = 0.1
		return
	}

	// Calculate time-weighted presence for each dimension
	recentWindow := time.Duration(30) * time.Second
	lastPointTime := mdb.Points[len(mdb.Points)-1].Timestamp

	// Find the start of the recent window
	recentStart := lastPointTime.Add(-recentWindow)

	// Count points and presence in recent and historical windows
	type dimStats struct {
		recentPresent, recentTotal    int
		historicalPresent, historical int
	}
	dimPresence := make(map[string]dimStats)

	// Initialize counters for all dimensions
	for dim := range allDims {
		dimPresence[dim] = dimStats{}
	}

	// Count points and presence
	for _, point := range mdb.Points {
		isRecent := point.Timestamp.After(recentStart)

		// Update total counts
		for dim := range allDims {
			stats := dimPresence[dim]

			if isRecent {
				stats.recentTotal++
			} else {
				stats.historical++
			}

			// Check if dimension is present
			if _, exists := point.Values[dim]; exists {
				if isRecent {
					stats.recentPresent++
				} else {
					stats.historicalPresent++
				}
			}

			dimPresence[dim] = stats
		}
	}

	// Calculate coverage for each dimension
	var totalCoverage float64
	for dim := range allDims {
		stats := dimPresence[dim]

		// Calculate recent and historical ratios
		recentRatio := float64(stats.recentPresent) / math.Max(float64(stats.recentTotal), 1.0)
		historicalRatio := float64(stats.historicalPresent) / math.Max(float64(stats.historical), 1.0)

		// Weight recent data more heavily (70/30 split)
		dimCoverage := (0.7 * recentRatio) + (0.3 * historicalRatio)
		totalCoverage += dimCoverage
	}

	// Calculate average coverage across dimensions
	mdb.Quality.Coverage = totalCoverage / float64(len(allDims))

	// Calculate gap penalty
	var gapPenalty float64
	lastSeen := make(map[string]time.Time)
	for _, point := range mdb.Points {
		for dim := range point.Values {
			lastSeen[dim] = point.Timestamp
		}
	}

	// Apply heavier penalties for recent gaps
	for dim := range allDims {
		if last, ok := lastSeen[dim]; ok {
			gap := lastPointTime.Sub(last)
			if gap > 2*mdb.Config.UpdateInterval {
				penalty := math.Min(1.0, float64(gap)/float64(10*mdb.Config.UpdateInterval))
				if gap <= recentWindow {
					gapPenalty += 2 * penalty // Double penalty for recent gaps
				} else {
					gapPenalty += penalty
				}
			}
		} else {
			gapPenalty += 1.0 // Maximum penalty for never-seen dimensions
		}
	}
	gapPenalty = math.Min(1.0, gapPenalty/float64(len(allDims)))

	// Calculate stability
	stability := mdb.calculateStability()

	// Combine metrics with adjusted weights
	// Coverage is weighted more heavily (60%) compared to stability (40%)
	// Both are penalized by gaps
	adjustedCoverage := mdb.Quality.Coverage * (1 - 0.7*gapPenalty)
	adjustedStability := stability * (1 - 0.3*gapPenalty)

	mdb.Quality.DataQuality = (0.6 * adjustedCoverage) + (0.4 * adjustedStability)
	mdb.Quality.Stability = adjustedStability

	// Ensure minimum quality of 0.1
	mdb.Quality.DataQuality = math.Max(0.1, mdb.Quality.DataQuality)
}

// calculateStability calculates the stability of the baseline
func (mdb *MultiDimBaseline) calculateStability() float64 {
	if len(mdb.Points) < 2 {
		return 0.1
	}

	// Calculate stability per dimension
	var totalStability float64
	var dimensionCount int

	for dim := range mdb.Dimensions {
		// Get values for this dimension
		var values []float64
		var timestamps []time.Time
		for _, point := range mdb.Points {
			if val, exists := point.Values[dim]; exists {
				values = append(values, val)
				timestamps = append(timestamps, point.Timestamp)
			}
		}

		if len(values) < 2 {
			continue
		}

		// Calculate differences between consecutive values
		var diffs []float64
		var timeDiffs []float64
		for i := 1; i < len(values); i++ {
			diffs = append(diffs, values[i]-values[i-1])
			timeDiffs = append(timeDiffs, float64(timestamps[i].Sub(timestamps[i-1]).Milliseconds()))
		}

		// Calculate mean and variance of differences
		var meanDiff, meanTimeDiff float64
		for i := range diffs {
			meanDiff += diffs[i]
			meanTimeDiff += timeDiffs[i]
		}
		meanDiff /= float64(len(diffs))
		meanTimeDiff /= float64(len(timeDiffs))

		var varDiff float64
		for _, diff := range diffs {
			d := diff - meanDiff
			varDiff += d * d
		}
		varDiff /= float64(len(diffs))

		// Calculate relative variance (coefficient of variation)
		var stability float64
		if meanDiff != 0 {
			cv := math.Sqrt(varDiff) / math.Abs(meanDiff)
			if cv < 0.1 {
				// Linear progression (very stable)
				stability = 1.0
			} else {
				// Variable pattern - use coefficient of variation
				stability = 0.5 + 0.4/(1.0+cv)
			}
		} else if varDiff < 0.0001 {
			// Constant value (perfectly stable)
			stability = 1.0
		} else {
			// Fluctuating around zero
			stability = 0.5
		}

		// Apply time regularity penalty
		var timeRegularity float64
		if meanTimeDiff > 0 {
			var varTime float64
			for _, td := range timeDiffs {
				d := td - meanTimeDiff
				varTime += d * d
			}
			varTime /= float64(len(timeDiffs))
			cvTime := math.Sqrt(varTime) / meanTimeDiff
			timeRegularity = 1.0 / (1.0 + cvTime)
		}

		// Combine value stability with time regularity
		stability = 0.7*stability + 0.3*timeRegularity
		totalStability += stability
		dimensionCount++
	}

	if dimensionCount == 0 {
		return 0.1
	}

	return totalStability / float64(dimensionCount)
}

// GetDimensionStats returns statistics for a specific dimension
func (mdb *MultiDimBaseline) GetDimensionStats(dimension string) (*DimensionStats, error) {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	stats, exists := mdb.Dimensions[dimension]
	if !exists {
		return nil, fmt.Errorf("dimension not found: %s", dimension)
	}
	return stats, nil
}

// GetCorrelation returns the correlation between two dimensions
func (mdb *MultiDimBaseline) GetCorrelation(dim1, dim2 string) (float64, error) {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	// Always use lexicographically ordered dimensions for key
	key := fmt.Sprintf("%s:%s", dim1, dim2)
	if dim2 < dim1 {
		key = fmt.Sprintf("%s:%s", dim2, dim1)
	}

	corr, exists := mdb.DimensionCorrelations[key]
	if !exists {
		return 0, fmt.Errorf("correlation not found for dimensions: %s, %s", dim1, dim2)
	}
	return corr.GetCorrelation(), nil
}

// GetQualityMetrics returns the current quality metrics
func (mdb *MultiDimBaseline) GetQualityMetrics() map[string]interface{} {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	return map[string]interface{}{
		"coverage":     mdb.Quality.Coverage,
		"stability":    mdb.Quality.Stability,
		"data_quality": mdb.Quality.DataQuality,
		"last_update":  mdb.Quality.LastUpdate,
	}
}

// Implement HealthAssessor interface
func (mdb *MultiDimBaseline) AssessHealth() BaselineHealth {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	health := BaselineHealth{
		DataPoints: len(mdb.Points),
		LastUpdate: mdb.Quality.LastUpdate,
		Coverage:   mdb.Quality.Coverage,
		Stability:  mdb.Quality.Stability,
		Confidence: mdb.Quality.DataQuality, // Map DataQuality to Confidence

		// Initialize maps
		ProtocolCoverage:   make(map[string]float64),
		ProtocolMaturity:   make(map[string]float64),
		ProtocolStability:  make(map[string]float64),
		TimeWindowCoverage: make(map[string]float64),
	}

	// Calculate learning progress
	if mdb.Config.MinDataPoints > 0 {
		health.LearningProgress = math.Min(1.0, float64(len(mdb.Points))/float64(mdb.Config.MinDataPoints))
	}

	// Set learning phase
	if health.LearningProgress < 1.0 {
		health.LearningPhase = "Initial"
	} else if health.Stability < 0.8 {
		health.LearningPhase = "Active"
	} else {
		health.LearningPhase = "Stable"
	}

	// Calculate dimension-specific metrics
	for dim := range mdb.Dimensions {
		health.ProtocolCoverage[dim] = mdb.calculateDimensionCoverage(dim)
		health.ProtocolMaturity[dim] = mdb.calculateDimensionMaturity(dim)
		health.ProtocolStability[dim] = mdb.calculateDimensionStability(dim)
	}

	// Calculate temporal coverage
	health.TimeWindowCoverage["hourly"] = mdb.calculateHourlyCoverage()
	health.TimeWindowCoverage["daily"] = mdb.calculateDailyCoverage()
	health.TimeWindowCoverage["monthly"] = mdb.calculateMonthlyCoverage()

	return health
}

func (mdb *MultiDimBaseline) GetStatus() BaselineHealthStatus {
	health := mdb.AssessHealth()
	issues := mdb.GetIssues()

	status := "Stable"
	if len(issues) > 0 {
		if health.Confidence < 0.5 { // Use Confidence instead of DataQuality
			status = "Unhealthy"
		} else {
			status = "Degraded"
		}
	} else if health.LearningPhase != "Stable" {
		status = "Learning"
	}

	return BaselineHealthStatus{
		Status:          status,
		Score:           health.Confidence, // Use Confidence instead of DataQuality
		Issues:          issues,
		LastAssessment:  time.Now(),
		LearningStatus:  health.LearningPhase,
		CoverageStatus:  mdb.getCoverageStatus(health.Coverage),
		StabilityStatus: mdb.getStabilityStatus(health.Stability),
		QualityStatus:   mdb.getQualityStatus(health.Confidence), // Use Confidence
	}
}

func (mdb *MultiDimBaseline) IsHealthy() bool {
	status := mdb.GetStatus()
	return status.Status == "Stable" || status.Status == "Learning"
}

func (mdb *MultiDimBaseline) GetIssues() []string {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	var issues []string

	// Check coverage
	if mdb.Quality.Coverage < 0.8 {
		issues = append(issues, fmt.Sprintf("Low coverage: %.1f%%", mdb.Quality.Coverage*100))
	}

	// Check stability
	if mdb.Quality.Stability < 0.7 {
		issues = append(issues, fmt.Sprintf("Low stability: %.1f%%", mdb.Quality.Stability*100))
	}

	// Check data quality
	if mdb.Quality.DataQuality < 0.8 {
		issues = append(issues, fmt.Sprintf("Poor data quality: %.1f%%", mdb.Quality.DataQuality*100))
	}

	// Check dimension presence
	for dim := range mdb.Dimensions {
		if coverage := mdb.calculateDimensionCoverage(dim); coverage < 0.6 {
			issues = append(issues, fmt.Sprintf("Low coverage for dimension %s: %.1f%%", dim, coverage*100))
		}
	}

	return issues
}

func (mdb *MultiDimBaseline) GetHealth() BaselineHealth {
	return mdb.AssessHealth()
}

// Helper methods for status assessment
func (mdb *MultiDimBaseline) getCoverageStatus(coverage float64) string {
	if coverage >= 0.9 {
		return "Good"
	} else if coverage >= 0.7 {
		return "Fair"
	}
	return "Poor"
}

func (mdb *MultiDimBaseline) getStabilityStatus(stability float64) string {
	if stability >= 0.9 {
		return "Good"
	} else if stability >= 0.7 {
		return "Fair"
	}
	return "Poor"
}

func (mdb *MultiDimBaseline) getQualityStatus(quality float64) string {
	if quality >= 0.9 {
		return "Good"
	} else if quality >= 0.7 {
		return "Fair"
	}
	return "Poor"
}

// Helper methods for dimension-specific metrics
func (mdb *MultiDimBaseline) calculateDimensionCoverage(dim string) float64 {
	var present int
	for _, point := range mdb.Points {
		if _, exists := point.Values[dim]; exists {
			present++
		}
	}
	return float64(present) / float64(len(mdb.Points))
}

func (mdb *MultiDimBaseline) calculateDimensionMaturity(dim string) float64 {
	if stats, exists := mdb.Dimensions[dim]; exists {
		count := stats.Variance.GetCount()
		return math.Min(1.0, float64(count)/float64(mdb.Config.MinDataPoints))
	}
	return 0.0
}

func (mdb *MultiDimBaseline) calculateDimensionStability(dim string) float64 {
	if stats, exists := mdb.Dimensions[dim]; exists && stats.Variance.GetCount() > 0 {
		cv := math.Sqrt(stats.Variance.GetVariance()) / stats.EWMA.GetValue()
		return 1.0 / (1.0 + cv)
	}
	return 0.0
}

// Temporal coverage calculations
func (mdb *MultiDimBaseline) calculateHourlyCoverage() float64 {
	hours := make(map[int]bool)
	for _, point := range mdb.Points {
		hours[point.Timestamp.Hour()] = true
	}
	return float64(len(hours)) / 24.0
}

func (mdb *MultiDimBaseline) calculateDailyCoverage() float64 {
	days := make(map[time.Weekday]bool)
	for _, point := range mdb.Points {
		days[point.Timestamp.Weekday()] = true
	}
	return float64(len(days)) / 7.0
}

func (mdb *MultiDimBaseline) calculateMonthlyCoverage() float64 {
	months := make(map[time.Month]bool)
	for _, point := range mdb.Points {
		months[point.Timestamp.Month()] = true
	}
	return float64(len(months)) / 12.0
}

// multiDimState represents the state to be saved/loaded
type multiDimState struct {
	Dimensions            map[string]*DimensionStats
	Points                []MultiDimPoint
	DimensionCorrelations map[string]*CorrelationTracker
	SeasonalityDetector   *SeasonalityDetector
	DimensionHistory      map[string][]time.Time
	History               DimensionHistory
	Quality               struct {
		Coverage    float64
		Stability   float64
		LastUpdate  time.Time
		DataQuality float64
	}
	Config struct {
		MinDataPoints  int
		MaxDataPoints  int
		WindowSize     time.Duration
		UpdateInterval time.Duration
	}
}

// Save persists the baseline state to a file
func (mdb *MultiDimBaseline) Save(path string) error {
	mdb.mu.RLock()
	defer mdb.mu.RUnlock()

	log.Printf("Saving baseline state to %s", path)

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Create state snapshot
	state := multiDimState{
		Dimensions:            mdb.Dimensions,
		Points:                mdb.Points,
		DimensionCorrelations: mdb.DimensionCorrelations,
		SeasonalityDetector:   mdb.SeasonalityDetector,
		DimensionHistory:      mdb.DimensionHistory,
		History:               mdb.history,
	}
	state.Quality = mdb.Quality
	state.Config = mdb.Config
	state.Config.MaxDataPoints = mdb.MaxPoints

	log.Printf("Created state snapshot with %d points and %d dimensions", len(state.Points), len(state.Dimensions))
	log.Printf("Saving dimensions: %v", state.Dimensions)
	if len(state.Points) > 0 {
		log.Printf("First point: %+v", state.Points[0])
	}
	if state.SeasonalityDetector != nil {
		log.Printf("Seasonality patterns: %v", state.SeasonalityDetector.Patterns)
	}

	// First encode to buffer to ensure we have a valid state before writing to file
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(state); err != nil {
		return fmt.Errorf("failed to encode state: %v", err)
	}

	// Create temporary file
	tempFile := path + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	file, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}

	// Ensure cleanup of temporary file in case of errors
	removeTemp := true
	defer func() {
		file.Close()
		if removeTemp {
			os.Remove(tempFile)
		}
	}()

	// Write buffer to file
	if _, err := buf.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write state to file: %v", err)
	}

	// Ensure all data is written
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %v", err)
	}

	// Close the file before renaming
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %v", err)
	}

	// Atomically rename temporary file
	if err := os.Rename(tempFile, path); err != nil {
		return fmt.Errorf("failed to rename file: %v", err)
	}

	// Successfully renamed, don't remove the temp file
	removeTemp = false

	log.Printf("Successfully saved baseline state to %s", path)
	return nil
}

// Load restores the baseline state from a file
func (mdb *MultiDimBaseline) Load(path string) error {
	mdb.mu.Lock()
	defer mdb.mu.Unlock()

	log.Printf("Loading baseline state from %s", path)

	// Open file
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Read entire file into buffer
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, file); err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Decode state
	var state multiDimState
	decoder := gob.NewDecoder(&buf)
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("failed to decode state: %v", err)
	}

	log.Printf("Loaded state with %d points and %d dimensions", len(state.Points), len(state.Dimensions))

	// Validate state
	if err := mdb.validateState(&state); err != nil {
		return fmt.Errorf("invalid state: %v", err)
	}

	// Initialize maps if they don't exist
	if mdb.Dimensions == nil {
		mdb.Dimensions = make(map[string]*DimensionStats)
	}
	if mdb.DimensionCorrelations == nil {
		mdb.DimensionCorrelations = make(map[string]*CorrelationTracker)
	}
	if mdb.DimensionHistory == nil {
		mdb.DimensionHistory = make(map[string][]time.Time)
	}
	if mdb.history.LastSeen == nil {
		mdb.history.LastSeen = make(map[string]time.Time)
	}

	// Debug: Compare dimensions
	log.Printf("Original dimensions: %v", mdb.Dimensions)
	log.Printf("Loaded dimensions: %v", state.Dimensions)

	// Debug: Compare points
	if len(mdb.Points) != len(state.Points) {
		log.Printf("Point count mismatch: original %d, loaded %d", len(mdb.Points), len(state.Points))
	}
	if len(mdb.Points) > 0 && len(state.Points) > 0 {
		log.Printf("First original point: %+v", mdb.Points[0])
		log.Printf("First loaded point: %+v", state.Points[0])
	}

	// Debug: Compare seasonality detector
	if mdb.SeasonalityDetector != nil && state.SeasonalityDetector != nil {
		log.Printf("Original seasonality patterns: %v", mdb.SeasonalityDetector.Patterns)
		log.Printf("Loaded seasonality patterns: %v", state.SeasonalityDetector.Patterns)
	}

	// Apply state
	mdb.Dimensions = state.Dimensions
	mdb.Points = state.Points
	mdb.DimensionCorrelations = state.DimensionCorrelations
	mdb.SeasonalityDetector = state.SeasonalityDetector
	mdb.DimensionHistory = state.DimensionHistory
	mdb.history = state.History
	mdb.Quality = state.Quality
	mdb.Config = state.Config
	mdb.MaxPoints = state.Config.MaxDataPoints
	mdb.UpdateCounter = len(state.Points) // Set counter to number of points

	log.Printf("Successfully loaded baseline state from %s", path)
	return nil
}

// validateState performs basic validation of loaded state
func (mdb *MultiDimBaseline) validateState(state *multiDimState) error {
	if state == nil {
		return fmt.Errorf("nil state")
	}

	// Validate required maps
	if state.Dimensions == nil {
		return fmt.Errorf("nil dimensions")
	}
	if state.DimensionCorrelations == nil {
		return fmt.Errorf("nil dimension correlations")
	}
	if state.DimensionHistory == nil {
		return fmt.Errorf("nil dimension history")
	}
	if state.History.LastSeen == nil {
		return fmt.Errorf("nil last seen history")
	}

	// Validate dimensions match
	for dim := range state.Dimensions {
		if _, exists := mdb.Dimensions[dim]; !exists {
			return fmt.Errorf("unknown dimension in state: %s", dim)
		}
	}

	// Validate component states
	for _, stats := range state.Dimensions {
		if stats.Variance == nil {
			return fmt.Errorf("nil variance tracker in dimension stats")
		}
		if stats.EWMA == nil {
			return fmt.Errorf("nil EWMA in dimension stats")
		}
	}

	// Validate seasonality detector
	if state.SeasonalityDetector == nil {
		return fmt.Errorf("nil seasonality detector")
	}
	if state.SeasonalityDetector.Patterns == nil {
		return fmt.Errorf("nil seasonality patterns")
	}

	return nil
}
