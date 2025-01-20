package baseline

import (
	"encoding/gob"
	"log"
	"math"
	"sort"
	"sync"
)

func init() {
	// Register types for gob encoding
	gob.Register(&VarianceTracker{})
	gob.Register(&CorrelationTracker{})
}

// QuantileEstimator implements the P-Square algorithm for online quantile estimation
type QuantileEstimator struct {
	Quantile float64    // Target quantile (0-1)
	N        int        // Count of observations
	Q        [5]float64 // Position markers
	DN       [5]float64 // Desired positions
	N_       [5]int     // Actual positions
}

// NewQuantileEstimator creates a new P-Square quantile estimator
func NewQuantileEstimator(quantile float64) *QuantileEstimator {
	qe := &QuantileEstimator{
		Quantile: quantile,
		Q:        [5]float64{},
		DN:       [5]float64{},
		N_:       [5]int{1, 2, 3, 4, 5},
	}
	return qe
}

// Update updates the quantile estimator with a new value
func (qe *QuantileEstimator) Update(value float64) {
	if qe.N < 5 {
		// Initial phase: collect 5 observations
		qe.Q[qe.N] = value
		qe.N++
		if qe.N == 5 {
			// Sort initial observations
			sort.Float64s(qe.Q[:])
			// Initialize desired positions
			qe.DN[0] = 1
			qe.DN[1] = 1 + 2*qe.Quantile
			qe.DN[2] = 1 + 4*qe.Quantile
			qe.DN[3] = 3 + 2*qe.Quantile
			qe.DN[4] = 5
		}
		return
	}

	// Find cell k where value belongs
	k := 0
	if value < qe.Q[0] {
		qe.Q[0] = value
	} else if value >= qe.Q[4] {
		qe.Q[4] = value
	} else {
		for k = 1; value >= qe.Q[k]; k++ {
		}
		// Increment positions of markers k+1 to 5
		for i := k; i < 5; i++ {
			qe.N_[i]++
		}
	}

	// Update desired positions
	for i := 0; i < 5; i++ {
		qe.DN[i] = float64(i+1)*qe.Quantile + float64(1)
	}

	// Adjust heights of markers 1 to 3 if necessary
	for i := 1; i < 4; i++ {
		n := float64(qe.N_[i])
		d := qe.DN[i]
		qi := qe.Q[i]
		qip1 := qe.Q[i+1]
		qim1 := qe.Q[i-1]

		// P-Square adjustment
		d1 := d - n
		d2 := n - float64(qe.N_[i-1])

		if (d1 >= 1 && d2 > 1) || (d1 > 1 && d2 >= 1) {
			// Adjustment needed
			qp := qi + ((qip1-qi)/(float64(qe.N_[i+1]-qe.N_[i])))*d1
			if qp > qim1 && qp < qip1 {
				qe.Q[i] = qp
			} else {
				// Use linear formula
				qe.Q[i] = qi + (qip1-qim1)/(float64(qe.N_[i+1]-qe.N_[i-1]))*d1
			}
		}
	}
	qe.N++
}

// GetQuantile returns the current quantile estimate
func (qe *QuantileEstimator) GetQuantile() float64 {
	if qe.N < 5 {
		// Not enough data for P-Square algorithm
		tmp := make([]float64, qe.N)
		copy(tmp, qe.Q[:qe.N])
		sort.Float64s(tmp)
		idx := int(float64(qe.N-1) * qe.Quantile)
		return tmp[idx]
	}
	return qe.Q[2] // Middle marker is the quantile estimate
}

// CorrelationTracker implements online correlation calculation
type CorrelationTracker struct {
	mu sync.RWMutex

	Count       int     // Number of samples
	MeanX       float64 // Mean of X values
	MeanY       float64 // Mean of Y values
	M2X         float64 // Sum of squared differences from mean for X
	M2Y         float64 // Sum of squared differences from mean for Y
	Covariance  float64 // Running covariance
	Correlation float64 // Pearson correlation coefficient
}

// NewCorrelationTracker creates a new correlation tracker
func NewCorrelationTracker() *CorrelationTracker {
	return &CorrelationTracker{}
}

// Add adds a new pair of values to the correlation tracker
func (c *CorrelationTracker) Add(x, y float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// First value
	if c.Count == 0 {
		c.Count = 1
		c.MeanX = x
		c.MeanY = y
		return
	}

	// Update count
	c.Count++

	// Update means and variances using Welford's online algorithm
	dx := x - c.MeanX
	c.MeanX += dx / float64(c.Count)
	dx2 := x - c.MeanX
	c.M2X += dx * dx2

	dy := y - c.MeanY
	c.MeanY += dy / float64(c.Count)
	dy2 := y - c.MeanY
	c.M2Y += dy * dy2

	// Update covariance
	c.Covariance += dx * dy2

	// Update correlation coefficient
	if c.Count > 1 {
		varX := c.M2X / float64(c.Count-1)
		varY := c.M2Y / float64(c.Count-1)
		if varX > 0 && varY > 0 {
			c.Correlation = c.Covariance / (math.Sqrt(varX*varY) * float64(c.Count-1))
		}
	}
}

// GetCorrelation returns the current Pearson correlation coefficient
func (c *CorrelationTracker) GetCorrelation() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Correlation
}

// Reset resets the correlation tracker
func (c *CorrelationTracker) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Count = 0
	c.MeanX = 0
	c.MeanY = 0
	c.M2X = 0
	c.M2Y = 0
	c.Covariance = 0
	c.Correlation = 0
}

// IsStrongCorrelation checks if there is a strong correlation (positive or negative)
func (c *CorrelationTracker) IsStrongCorrelation(threshold float64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Count < 2 {
		return false
	}

	return math.Abs(c.Correlation) >= threshold
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

	// Quantile estimators
	Median *QuantileEstimator // 50th percentile
	Q1     *QuantileEstimator // 25th percentile
	Q3     *QuantileEstimator // 75th percentile
	P95    *QuantileEstimator // 95th percentile
	P99    *QuantileEstimator // 99th percentile

	// Correlation trackers
	PacketByteCorr    *CorrelationTracker // Correlation between packet and byte counts
	PacketBurstCorr   *CorrelationTracker // Correlation between packet counts and burst sizes
	ByteBurstCorr     *CorrelationTracker // Correlation between byte counts and burst sizes
	TemporalCorr      *CorrelationTracker // Correlation with previous time window
	LastValue         float64             // Last value added (for temporal correlation)
	LastTemporalValue float64             // Previous window's value
}

// NewVarianceTracker creates a new variance tracker
func NewVarianceTracker() *VarianceTracker {
	return &VarianceTracker{
		Min:    math.Inf(1),  // Initialize to positive infinity
		Max:    math.Inf(-1), // Initialize to negative infinity
		Median: NewQuantileEstimator(0.5),
		Q1:     NewQuantileEstimator(0.25),
		Q3:     NewQuantileEstimator(0.75),
		P95:    NewQuantileEstimator(0.95),
		P99:    NewQuantileEstimator(0.99),

		// Initialize correlation trackers
		PacketByteCorr:  NewCorrelationTracker(),
		PacketBurstCorr: NewCorrelationTracker(),
		ByteBurstCorr:   NewCorrelationTracker(),
		TemporalCorr:    NewCorrelationTracker(),
	}
}

// AddCorrelatedMetrics adds correlated metrics (packets, bytes, burst size)
func (v *VarianceTracker) AddCorrelatedMetrics(packets, bytes, burstSize float64) {
	// First update correlation trackers with their own locks
	v.PacketByteCorr.Add(packets, bytes)
	v.PacketBurstCorr.Add(packets, burstSize)
	v.ByteBurstCorr.Add(bytes, burstSize)

	// Then update temporal correlation
	v.mu.Lock()
	if v.Count > 0 {
		v.TemporalCorr.Add(v.LastValue, packets)
	}
	v.LastTemporalValue = v.LastValue
	v.LastValue = packets
	v.mu.Unlock()

	// Finally update base statistics
	v.Add(packets)
}

// GetCorrelations returns all correlation coefficients
func (v *VarianceTracker) GetCorrelations() map[string]float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return map[string]float64{
		"packet_byte_correlation":  v.PacketByteCorr.GetCorrelation(),
		"packet_burst_correlation": v.PacketBurstCorr.GetCorrelation(),
		"byte_burst_correlation":   v.ByteBurstCorr.GetCorrelation(),
		"temporal_correlation":     v.TemporalCorr.GetCorrelation(),
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

	// Update quantile estimators
	v.Median.Update(value)
	v.Q1.Update(value)
	v.Q3.Update(value)
	v.P95.Update(value)
	v.P99.Update(value)

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

// GetQuantiles returns the current quantile estimates
func (v *VarianceTracker) GetQuantiles() (q1, median, q3, p95, p99 float64) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	q1 = v.Q1.GetQuantile()
	median = v.Median.GetQuantile()
	q3 = v.Q3.GetQuantile()
	p95 = v.P95.GetQuantile()
	p99 = v.P99.GetQuantile()
	return
}

// GetIQR returns the Interquartile Range (Q3 - Q1)
func (v *VarianceTracker) GetIQR() float64 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.Q3.GetQuantile() - v.Q1.GetQuantile()
}

// IsQuantileAnomaly checks if a value is anomalous based on its position relative to the IQR
func (v *VarianceTracker) IsQuantileAnomaly(value float64) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.Count < 5 {
		return false
	}

	q1 := v.Q1.GetQuantile()
	q3 := v.Q3.GetQuantile()
	iqr := q3 - q1

	// Use 1.5 * IQR rule for outlier detection
	lowerBound := q1 - 1.5*iqr
	upperBound := q3 + 1.5*iqr

	return value < lowerBound || value > upperBound
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
	v.LastValue = 0
	v.LastTemporalValue = 0

	// Reset quantile estimators
	v.Median = NewQuantileEstimator(0.5)
	v.Q1 = NewQuantileEstimator(0.25)
	v.Q3 = NewQuantileEstimator(0.75)
	v.P95 = NewQuantileEstimator(0.95)
	v.P99 = NewQuantileEstimator(0.99)

	// Reset correlation trackers
	v.PacketByteCorr.Reset()
	v.PacketBurstCorr.Reset()
	v.ByteBurstCorr.Reset()
	v.TemporalCorr.Reset()
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
