package baseline

import (
	"encoding/gob"
	"fmt"
	"math"
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
