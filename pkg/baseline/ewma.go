package baseline

import (
	"math"
	"sync"
)

// EWMA implements an exponentially weighted moving average
type EWMA struct {
	mu    sync.RWMutex
	alpha float64 // Smoothing factor (0 < alpha <= 1)
	value float64 // Current EWMA value
	count int     // Number of samples
}

// NewEWMA creates a new EWMA with the given alpha value
func NewEWMA(alpha float64) *EWMA {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1 // Default to reasonable value if invalid
	}
	return &EWMA{
		alpha: alpha,
	}
}

// Update adds a new value to the EWMA
func (e *EWMA) Update(value float64) {
	// Handle NaN and Inf values
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.count++
	if e.count == 1 {
		e.value = value
		return
	}

	// EWMA formula: value = alpha * new_value + (1 - alpha) * old_value
	e.value = e.alpha*value + (1-e.alpha)*e.value
}

// GetValue returns the current EWMA value
func (e *EWMA) GetValue() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.value
}

// Reset resets the EWMA to its initial state
func (e *EWMA) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.value = 0
	e.count = 0
}

// GetCount returns the number of samples processed
func (e *EWMA) GetCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.count
}

// GetAlpha returns the smoothing factor
func (e *EWMA) GetAlpha() float64 {
	return e.alpha // Immutable after creation, no lock needed
}

// GetConfidenceBounds returns the confidence bounds for the EWMA
// Returns (lower bound, upper bound) for the given confidence level (e.g., 0.95 for 95%)
func (e *EWMA) GetConfidenceBounds(confidence float64) (float64, float64) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.count < 2 {
		return e.value, e.value
	}

	// Calculate standard error
	// For EWMA, SE = sqrt(alpha/(2-alpha)) * sigma
	// We'll use a simplified approximation here
	standardError := math.Sqrt(e.alpha/(2-e.alpha)) * math.Abs(e.value) * 0.1

	// Z-score for the confidence interval
	// 1.96 for 95% confidence, 2.576 for 99% confidence
	zScore := 1.96
	if confidence > 0.95 {
		zScore = 2.576
	}

	margin := zScore * standardError
	return e.value - margin, e.value + margin
}
