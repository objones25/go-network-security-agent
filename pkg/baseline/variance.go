package baseline

import (
	"log"
	"math"
	"sync"
)

// VarianceTracker implements Welford's online algorithm for computing variance
type VarianceTracker struct {
	mu sync.RWMutex

	count      int     // Number of samples
	mean       float64 // Current mean
	m2         float64 // Sum of squared differences from mean
	min        float64 // Minimum value seen
	max        float64 // Maximum value seen
	lastZScore float64 // Last computed z-score
}

// NewVarianceTracker creates a new variance tracker
func NewVarianceTracker() *VarianceTracker {
	return &VarianceTracker{
		min: math.Inf(1),  // Initialize to positive infinity
		max: math.Inf(-1), // Initialize to negative infinity
	}
}

// Add adds a new value to the variance tracker
func (v *VarianceTracker) Add(value float64) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// First value
	if v.count == 0 {
		v.count = 1
		v.mean = value
		v.min = value
		v.max = value
		v.lastZScore = 0
		return
	}

	// Update count and mean
	v.count++
	oldMean := v.mean
	delta := value - oldMean
	v.mean += delta / float64(v.count)

	// Update M2 using Welford's online algorithm
	delta2 := value - v.mean
	v.m2 += delta * delta2

	// Update min/max
	if value < v.min {
		v.min = value
	}
	if value > v.max {
		v.max = value
	}

	// Compute z-score if we have enough samples
	if v.count > 1 {
		stdDev := math.Sqrt(v.m2 / float64(v.count-1))
		if stdDev > 0 {
			v.lastZScore = (value - v.mean) / stdDev
		} else {
			v.lastZScore = 0
		}
	}
}

// GetMean returns the current mean
func (v *VarianceTracker) GetMean() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.mean
}

// GetVariance returns the current variance
func (v *VarianceTracker) GetVariance() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.count < 2 {
		return 0
	}
	// Use Bessel's correction (n-1) for sample variance
	return v.m2 / float64(v.count-1)
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

	if v.count < 2 {
		return 0
	}

	stdDev := math.Sqrt(v.m2 / float64(v.count-1))
	if stdDev == 0 {
		return 0
	}

	return (value - v.mean) / stdDev
}

// GetLastZScore returns the z-score of the last added value
func (v *VarianceTracker) GetLastZScore() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastZScore
}

// GetCount returns the number of samples
func (v *VarianceTracker) GetCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.count
}

// GetMinMax returns the minimum and maximum values seen
func (v *VarianceTracker) GetMinMax() (float64, float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.min, v.max
}

// Reset resets the variance tracker to its initial state
func (v *VarianceTracker) Reset() {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.count = 0
	v.mean = 0
	v.m2 = 0
	v.min = math.Inf(1)
	v.max = math.Inf(-1)
	v.lastZScore = 0
}

// GetStats returns basic statistics
func (v *VarianceTracker) GetStats() (mean, stdDev, min, max float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	mean = v.mean
	min = v.min
	max = v.max
	if v.count >= 2 {
		stdDev = math.Sqrt(v.m2 / float64(v.count-1))
	}
	log.Printf("Stats: mean=%v, stdDev=%v, min=%v, max=%v", mean, stdDev, min, max)
	return
}

// GetConfidenceInterval returns the confidence interval for the mean
// confidence is the confidence level (e.g., 0.95 for 95% confidence)
func (v *VarianceTracker) GetConfidenceInterval(confidence float64) (lower, upper float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.count < 2 {
		return v.mean, v.mean
	}

	// Get z-score for confidence level
	// 1.96 for 95% confidence, 2.576 for 99% confidence
	zScore := 1.96
	if confidence > 0.95 {
		zScore = 2.576
	}

	stdError := math.Sqrt(v.GetVariance() / float64(v.count))
	margin := zScore * stdError

	return v.mean - margin, v.mean + margin
}

// IsAnomaly determines if a value is anomalous based on z-score threshold
func (v *VarianceTracker) IsAnomaly(value float64, threshold float64) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.count < 2 {
		return false
	}

	// Calculate sample standard deviation
	stdDev := math.Sqrt(v.m2 / float64(v.count-1))
	if stdDev < 1e-10 {
		// For nearly identical values, use relative difference
		relDiff := math.Abs(value-v.mean) / math.Abs(v.mean)
		return relDiff > 0.1 // 10% difference threshold for zero variance case
	}

	zScore := math.Abs((value - v.mean) / stdDev)
	return zScore > threshold
}
