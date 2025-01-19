package baseline

import (
	"encoding/gob"
	"math"
	"sync"
)

func init() {
	// Register EWMA type for gob encoding
	gob.Register(&EWMA{})
}

// EWMA implements an exponentially weighted moving average
type EWMA struct {
	mu    sync.RWMutex
	Alpha float64 // Smoothing factor (0 < alpha <= 1)
	Value float64 // Current EWMA value
	Count int     // Number of samples
}

// NewEWMA creates a new EWMA with the given alpha value
func NewEWMA(alpha float64) *EWMA {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1 // Default to reasonable value if invalid
	}
	return &EWMA{
		Alpha: alpha,
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

	e.Count++
	if e.Count == 1 {
		e.Value = value
		return
	}

	// EWMA formula: value = alpha * new_value + (1 - alpha) * old_value
	e.Value = e.Alpha*value + (1-e.Alpha)*e.Value
}

// GetValue returns the current EWMA value
func (e *EWMA) GetValue() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Value
}

// Reset resets the EWMA to its initial state
func (e *EWMA) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Value = 0
	e.Count = 0
}

// GetCount returns the number of samples processed
func (e *EWMA) GetCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Count
}

// GetAlpha returns the smoothing factor
func (e *EWMA) GetAlpha() float64 {
	return e.Alpha // Immutable after creation, no lock needed
}

// GetConfidenceBounds returns the confidence bounds for the EWMA
// Returns (lower bound, upper bound) for the given confidence level (e.g., 0.95 for 95%)
func (e *EWMA) GetConfidenceBounds(confidence float64) (float64, float64) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.Count < 2 {
		return e.Value, e.Value
	}

	// Calculate standard error
	// For EWMA, SE = sqrt(alpha/(2-alpha)) * sigma
	// We'll use a simplified approximation here
	standardError := math.Sqrt(e.Alpha/(2-e.Alpha)) * math.Abs(e.Value) * 0.1

	// Z-score for the confidence interval
	// 1.96 for 95% confidence, 2.576 for 99% confidence
	zScore := 1.96
	if confidence > 0.95 {
		zScore = 2.576
	}

	margin := zScore * standardError
	return e.Value - margin, e.Value + margin
}
