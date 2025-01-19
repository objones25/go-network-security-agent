package baseline

import (
	"encoding/gob"
	"log"
	"math"
	"sync"
)

func init() {
	// Register VarianceTracker type for gob encoding
	gob.Register(&VarianceTracker{})
}

// VarianceTracker implements Welford's online algorithm for computing variance
type VarianceTracker struct {
	mu sync.RWMutex

	Count      int     // Number of samples
	Mean       float64 // Current mean
	M2         float64 // Sum of squared differences from mean
	Min        float64 // Minimum value seen
	Max        float64 // Maximum value seen
	LastZScore float64 // Last computed z-score
}

// NewVarianceTracker creates a new variance tracker
func NewVarianceTracker() *VarianceTracker {
	return &VarianceTracker{
		Min: math.Inf(1),  // Initialize to positive infinity
		Max: math.Inf(-1), // Initialize to negative infinity
	}
}

// Add adds a new value to the variance tracker
func (v *VarianceTracker) Add(value float64) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// First value
	if v.Count == 0 {
		v.Count = 1
		v.Mean = value
		v.Min = value
		v.Max = value
		v.LastZScore = 0
		return
	}

	// Update count and mean
	v.Count++
	oldMean := v.Mean
	delta := value - oldMean
	v.Mean += delta / float64(v.Count)

	// Update M2 using Welford's online algorithm
	delta2 := value - v.Mean
	v.M2 += delta * delta2

	// Update min/max
	if value < v.Min {
		v.Min = value
	}
	if value > v.Max {
		v.Max = value
	}

	// Compute z-score if we have enough samples
	if v.Count > 1 {
		stdDev := math.Sqrt(v.M2 / float64(v.Count-1))
		if stdDev > 0 {
			v.LastZScore = (value - v.Mean) / stdDev
		} else {
			v.LastZScore = 0
		}
	}
}

// GetMean returns the current mean
func (v *VarianceTracker) GetMean() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.Mean
}

// GetVariance returns the current variance
func (v *VarianceTracker) GetVariance() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.Count < 2 {
		return 0
	}
	// Use Bessel's correction (n-1) for sample variance
	return v.M2 / float64(v.Count-1)
}

// GetStdDev returns the current standard deviation
func (v *VarianceTracker) GetStdDev() float64 {
	variance := v.GetVariance()
	return math.Sqrt(variance)
}

// GetZScore returns the z-score for a given value
func (v *VarianceTracker) GetZScore(value float64) float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.Count < 2 {
		return 0
	}

	stdDev := math.Sqrt(v.M2 / float64(v.Count-1))
	if stdDev == 0 {
		return 0
	}

	return (value - v.Mean) / stdDev
}

// GetLastZScore returns the z-score of the last added value
func (v *VarianceTracker) GetLastZScore() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.LastZScore
}

// GetCount returns the number of samples
func (v *VarianceTracker) GetCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.Count
}

// GetMinMax returns the minimum and maximum values seen
func (v *VarianceTracker) GetMinMax() (float64, float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.Min, v.Max
}

// Reset resets the variance tracker to its initial state
func (v *VarianceTracker) Reset() {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.Count = 0
	v.Mean = 0
	v.M2 = 0
	v.Min = math.Inf(1)
	v.Max = math.Inf(-1)
	v.LastZScore = 0
}

// GetStats returns basic statistics
func (v *VarianceTracker) GetStats() (mean, stdDev, min, max float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	mean = v.Mean
	min = v.Min
	max = v.Max
	if v.Count >= 2 {
		stdDev = math.Sqrt(v.M2 / float64(v.Count-1))
	}
	log.Printf("Stats: mean=%v, stdDev=%v, min=%v, max=%v", mean, stdDev, min, max)
	return
}

// GetConfidenceInterval returns the confidence interval for the mean
// confidence is the confidence level (e.g., 0.95 for 95% confidence)
func (v *VarianceTracker) GetConfidenceInterval(confidence float64) (lower, upper float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.Count < 2 {
		return v.Mean, v.Mean
	}

	// Get z-score for confidence level
	// 1.96 for 95% confidence, 2.576 for 99% confidence
	zScore := 1.96
	if confidence > 0.95 {
		zScore = 2.576
	}

	stdError := math.Sqrt(v.GetVariance() / float64(v.Count))
	margin := zScore * stdError

	return v.Mean - margin, v.Mean + margin
}

// IsAnomaly determines if a value is anomalous based on z-score threshold
func (v *VarianceTracker) IsAnomaly(value float64, threshold float64) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.Count < 2 {
		return false
	}

	// Calculate sample standard deviation
	stdDev := math.Sqrt(v.M2 / float64(v.Count-1))
	if stdDev < 1e-10 {
		// For nearly identical values, use relative difference
		relDiff := math.Abs(value-v.Mean) / math.Abs(v.Mean)
		return relDiff > 0.1 // 10% difference threshold for zero variance case
	}

	zScore := math.Abs((value - v.Mean) / stdDev)
	return zScore > threshold
}
