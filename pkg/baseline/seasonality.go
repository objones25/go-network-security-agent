package baseline

import (
	"encoding/gob"
	"math"
	"sync"
	"time"
)

func init() {
	// Register types for gob encoding
	gob.Register(&SeasonalityDetector{})
	gob.Register(&SeasonalPattern{})
	gob.Register(map[string]*SeasonalPattern{})
}

// SeasonalPattern tracks seasonal patterns for a dimension
type SeasonalPattern struct {
	// Hourly patterns (0-23)
	HourlyPatterns map[int]*EWMA
	// Daily patterns (0-6, Sunday=0)
	DailyPatterns map[int]*EWMA
	// Monthly patterns (1-12)
	MonthlyPatterns map[int]*EWMA
	// Pattern strength (0-1)
	HourlyStrength  float64
	DailyStrength   float64
	MonthlyStrength float64
	// Last update
	LastUpdate time.Time
}

// SeasonalityDetector implements advanced seasonality detection
type SeasonalityDetector struct {
	mu sync.RWMutex

	// Patterns for each dimension
	Patterns map[string]*SeasonalPattern

	// Configuration
	UpdateInterval time.Duration
	MinDataPoints  int
	Alpha          float64 // EWMA smoothing factor

	// Detection thresholds
	Thresholds struct {
		MinPatternStrength float64
		MinDataPoints      int
		MaxGapDuration     time.Duration
	}
}

// NewSeasonalityDetector creates a new seasonality detector
func NewSeasonalityDetector(updateInterval time.Duration) *SeasonalityDetector {
	sd := &SeasonalityDetector{
		Patterns:       make(map[string]*SeasonalPattern),
		UpdateInterval: updateInterval,
		MinDataPoints:  100,
		Alpha:          0.1,
	}

	// Set default thresholds
	sd.Thresholds.MinPatternStrength = 0.3
	sd.Thresholds.MinDataPoints = 24 * 7 // One week of hourly data
	sd.Thresholds.MaxGapDuration = 6 * time.Hour

	return sd
}

// newSeasonalPattern creates a new seasonal pattern tracker
func newSeasonalPattern(alpha float64) *SeasonalPattern {
	sp := &SeasonalPattern{
		HourlyPatterns:  make(map[int]*EWMA),
		DailyPatterns:   make(map[int]*EWMA),
		MonthlyPatterns: make(map[int]*EWMA),
	}

	// Initialize hourly patterns
	for hour := 0; hour < 24; hour++ {
		sp.HourlyPatterns[hour] = NewEWMA(alpha)
	}

	// Initialize daily patterns
	for day := 0; day < 7; day++ {
		sp.DailyPatterns[day] = NewEWMA(alpha)
	}

	// Initialize monthly patterns
	for month := 1; month <= 12; month++ {
		sp.MonthlyPatterns[month] = NewEWMA(alpha)
	}

	return sp
}

// AddValue adds a new value for seasonality analysis
func (sd *SeasonalityDetector) AddValue(dimension string, value float64, timestamp time.Time) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	// Get or create pattern for dimension
	pattern, exists := sd.Patterns[dimension]
	if !exists {
		pattern = newSeasonalPattern(sd.Alpha)
		sd.Patterns[dimension] = pattern
	}

	// Update patterns
	hour := timestamp.Hour()
	pattern.HourlyPatterns[hour].Update(value)

	day := int(timestamp.Weekday())
	pattern.DailyPatterns[day].Update(value)

	month := int(timestamp.Month())
	pattern.MonthlyPatterns[month].Update(value)

	// Update pattern strengths periodically
	if pattern.LastUpdate.IsZero() || time.Since(pattern.LastUpdate) > sd.UpdateInterval {
		sd.updatePatternStrengths(pattern)
		pattern.LastUpdate = timestamp
	}
}

// GetSeasonalScore returns how well a value fits the seasonal pattern
func (sd *SeasonalityDetector) GetSeasonalScore(dimension string, value float64, timestamp time.Time) float64 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	pattern, exists := sd.Patterns[dimension]
	if !exists {
		return 1.0 // No pattern established yet
	}

	hour := timestamp.Hour()
	day := int(timestamp.Weekday())
	month := int(timestamp.Month())

	// Get expected values
	hourlyExpected := pattern.HourlyPatterns[hour].GetValue()
	dailyExpected := pattern.DailyPatterns[day].GetValue()
	monthlyExpected := pattern.MonthlyPatterns[month].GetValue()

	// Calculate deviations
	hourlyDev := math.Abs(value-hourlyExpected) / math.Max(1.0, hourlyExpected)
	dailyDev := math.Abs(value-dailyExpected) / math.Max(1.0, dailyExpected)
	monthlyDev := math.Abs(value-monthlyExpected) / math.Max(1.0, monthlyExpected)

	// Weight deviations by pattern strength
	weightedDev := (hourlyDev*pattern.HourlyStrength +
		dailyDev*pattern.DailyStrength +
		monthlyDev*pattern.MonthlyStrength) /
		math.Max(0.001, pattern.HourlyStrength+pattern.DailyStrength+pattern.MonthlyStrength)

	// Convert to score (0-1, higher is better match)
	return 1.0 / (1.0 + weightedDev)
}

// updatePatternStrengths updates the strength of detected patterns
func (sd *SeasonalityDetector) updatePatternStrengths(pattern *SeasonalPattern) {
	// Calculate hourly pattern strength
	hourlyVar := calculatePatternVariance(pattern.HourlyPatterns)
	pattern.HourlyStrength = 1.0 / (1.0 + hourlyVar)

	// Calculate daily pattern strength
	dailyVar := calculatePatternVariance(pattern.DailyPatterns)
	pattern.DailyStrength = 1.0 / (1.0 + dailyVar)

	// Calculate monthly pattern strength
	monthlyVar := calculatePatternVariance(pattern.MonthlyPatterns)
	pattern.MonthlyStrength = 1.0 / (1.0 + monthlyVar)
}

// calculatePatternVariance calculates variance between pattern values
func calculatePatternVariance(patterns map[int]*EWMA) float64 {
	if len(patterns) == 0 {
		return math.Inf(1)
	}

	// Calculate mean
	var sum float64
	var count int
	for _, p := range patterns {
		if p.GetCount() > 0 {
			sum += p.GetValue()
			count++
		}
	}
	if count == 0 {
		return math.Inf(1)
	}
	mean := sum / float64(count)

	// Calculate variance
	var variance float64
	for _, p := range patterns {
		if p.GetCount() > 0 {
			diff := p.GetValue() - mean
			variance += diff * diff
		}
	}
	variance /= float64(count)

	return variance
}

// GetPatternStrengths returns the current pattern strengths for a dimension
func (sd *SeasonalityDetector) GetPatternStrengths(dimension string) (hourly, daily, monthly float64, err error) {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	pattern, exists := sd.Patterns[dimension]
	if !exists {
		return 0, 0, 0, nil
	}

	return pattern.HourlyStrength, pattern.DailyStrength, pattern.MonthlyStrength, nil
}

// Reset resets the seasonality detector
func (sd *SeasonalityDetector) Reset() {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	sd.Patterns = make(map[string]*SeasonalPattern)
}
