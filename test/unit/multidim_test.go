package unit

import (
	"encoding/gob"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/baseline"
)

func TestMultiDimBaseline(t *testing.T) {
	// Test setup
	dimensions := []string{"packets", "bytes", "connections"}
	config := baseline.Config{
		UpdateInterval:  time.Second,
		MinSamples:      100,
		ShortTermAlpha:  0.3,
		MediumTermAlpha: 0.1,
		LongTermAlpha:   0.05,
	}

	// Create baseline
	mdb, err := baseline.NewMultiDimBaseline(dimensions, config)
	if err != nil {
		t.Fatalf("Failed to create multi-dimensional baseline: %v", err)
	}

	// Test initialization
	if len(mdb.Dimensions) != len(dimensions) {
		t.Errorf("Expected %d dimensions, got %d", len(dimensions), len(mdb.Dimensions))
	}

	// Test adding points
	testPoints := []baseline.MultiDimPoint{
		{
			Values: map[string]float64{
				"packets":     100,
				"bytes":       1500,
				"connections": 10,
			},
			Timestamp: time.Now(),
		},
		{
			Values: map[string]float64{
				"packets":     150,
				"bytes":       2250,
				"connections": 15,
			},
			Timestamp: time.Now().Add(time.Second),
		},
	}

	// Add test points
	for _, point := range testPoints {
		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point: %v", err)
		}
	}

	// Test dimension stats
	for _, dim := range dimensions {
		stats, err := mdb.GetDimensionStats(dim)
		if err != nil {
			t.Errorf("Failed to get stats for dimension %s: %v", dim, err)
			continue
		}

		if stats.Variance.GetCount() != len(testPoints) {
			t.Errorf("Expected %d samples for dimension %s, got %d",
				len(testPoints), dim, stats.Variance.GetCount())
		}
	}

	// Test correlation
	corr, err := mdb.GetCorrelation("packets", "bytes")
	if err != nil {
		t.Errorf("Failed to get correlation: %v", err)
	}
	if corr <= 0 {
		t.Errorf("Expected positive correlation between packets and bytes, got %f", corr)
	}

	// Test anomaly detection
	anomalyPoint := baseline.MultiDimPoint{
		Values: map[string]float64{
			"packets":     1000, // Significant deviation
			"bytes":       1500,
			"connections": 10,
		},
		Timestamp: time.Now().Add(2 * time.Second),
	}

	isAnomaly, scores := mdb.IsAnomaly(anomalyPoint)
	if !isAnomaly {
		t.Error("Expected anomaly detection for significant deviation")
	}
	if scores["packets"] <= scores["bytes"] {
		t.Error("Expected higher anomaly score for packets dimension")
	}

	// Test quality metrics
	metrics := mdb.GetQualityMetrics()
	if metrics["coverage"].(float64) <= 0 {
		t.Error("Expected non-zero coverage")
	}
	if metrics["stability"].(float64) <= 0 {
		t.Error("Expected non-zero stability")
	}
	if metrics["data_quality"].(float64) <= 0 {
		t.Error("Expected non-zero data quality")
	}
}

func TestSeasonalityDetection(t *testing.T) {
	dimensions := []string{"traffic"}
	config := baseline.Config{
		UpdateInterval:  time.Hour,
		MinSamples:      100,
		MediumTermAlpha: 0.1,
	}

	mdb, err := baseline.NewMultiDimBaseline(dimensions, config)
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Generate 24 hours of data with a clear pattern
	baseTime := time.Now().Truncate(time.Hour)
	for hour := 0; hour < 24; hour++ {
		// Create a daily pattern: higher during business hours
		value := 100.0
		if hour >= 9 && hour <= 17 {
			value = 500.0 // Business hours
		}

		point := baseline.MultiDimPoint{
			Values: map[string]float64{
				"traffic": value,
			},
			Timestamp: baseTime.Add(time.Duration(hour) * time.Hour),
		}

		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point at hour %d: %v", hour, err)
		}
	}

	// Test pattern detection
	stats, err := mdb.GetDimensionStats("traffic")
	if err != nil {
		t.Fatalf("Failed to get traffic stats: %v", err)
	}

	// Verify pattern statistics
	if stats.Variance.GetCount() != 24 {
		t.Errorf("Expected 24 samples, got %d", stats.Variance.GetCount())
	}

	mean := stats.Variance.GetMean()
	expectedMean := (9*100.0 + 9*500.0 + 6*100.0) / 24.0 // 9 off hours + 9 business hours + 6 evening hours
	if mean < expectedMean*0.9 || mean > expectedMean*1.1 {
		t.Errorf("Expected mean around %.2f, got %.2f", expectedMean, mean)
	}

	// Test anomaly detection during and outside business hours
	businessHourPoint := baseline.MultiDimPoint{
		Values: map[string]float64{
			"traffic": 1000.0, // Anomalous value during business hours
		},
		Timestamp: baseTime.Add(12 * time.Hour), // Noon
	}

	offHourPoint := baseline.MultiDimPoint{
		Values: map[string]float64{
			"traffic": 1000.0, // Same value, but during off hours
		},
		Timestamp: baseTime.Add(3 * time.Hour), // 3 AM
	}

	// The off-hour anomaly should have a higher anomaly score
	_, businessScores := mdb.IsAnomaly(businessHourPoint)
	_, offHourScores := mdb.IsAnomaly(offHourPoint)

	if businessScores["traffic"] >= offHourScores["traffic"] {
		t.Error("Expected higher anomaly score for off-hour traffic spike")
	}
}

func TestCorrelationViolations(t *testing.T) {
	dimensions := []string{"requests", "latency"}
	config := baseline.Config{
		UpdateInterval:  time.Second,
		MinSamples:      100,
		MediumTermAlpha: 0.1,
	}

	mdb, err := baseline.NewMultiDimBaseline(dimensions, config)
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Add points with strong positive correlation
	baseTime := time.Now()
	for i := 0; i < 100; i++ {
		point := baseline.MultiDimPoint{
			Values: map[string]float64{
				"requests": float64(100 + i),
				"latency":  float64(50 + i/2),
			},
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
		}
		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point %d: %v", i, err)
		}
	}

	// Verify correlation
	corr, err := mdb.GetCorrelation("requests", "latency")
	if err != nil {
		t.Fatalf("Failed to get correlation: %v", err)
	}
	if corr < 0.8 {
		t.Errorf("Expected strong positive correlation, got %f", corr)
	}

	// Test point that violates correlation
	violationPoint := baseline.MultiDimPoint{
		Values: map[string]float64{
			"requests": 500.0, // High requests
			"latency":  10.0,  // But low latency
		},
		Timestamp: baseTime.Add(101 * time.Second),
	}

	isAnomaly, scores := mdb.IsAnomaly(violationPoint)
	if !isAnomaly {
		t.Error("Expected anomaly detection for correlation violation")
	}

	// The anomaly score should reflect both individual metrics and correlation violation
	if scores["requests"] <= 0 || scores["latency"] <= 0 {
		t.Error("Expected non-zero anomaly scores for both dimensions")
	}
}

func TestDataQuality(t *testing.T) {
	dimensions := []string{"metric1", "metric2"}
	config := baseline.Config{
		UpdateInterval:  time.Second,
		MinSamples:      100,
		MediumTermAlpha: 0.1,
	}

	mdb, err := baseline.NewMultiDimBaseline(dimensions, config)
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Add points with good quality
	baseTime := time.Now()
	for i := 0; i < 50; i++ {
		point := baseline.MultiDimPoint{
			Values: map[string]float64{
				"metric1": float64(100 + i),
				"metric2": float64(200 + i),
			},
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
		}
		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point %d: %v", i, err)
		}
	}

	// Add points with gaps and missing dimensions
	for i := 0; i < 10; i++ {
		point := baseline.MultiDimPoint{
			Values: map[string]float64{
				"metric1": float64(150 + i),
			},
			Timestamp: baseTime.Add(time.Duration(60+i*10) * time.Second),
		}
		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point %d: %v", i, err)
		}
	}

	// Check quality metrics
	metrics := mdb.GetQualityMetrics()

	// Coverage should be less than 1.0 due to missing dimensions
	if metrics["coverage"].(float64) >= 1.0 {
		t.Error("Expected coverage less than 1.0 due to missing dimensions")
	}

	// Data quality should be affected by gaps and missing dimensions
	if metrics["data_quality"].(float64) >= 0.9 {
		t.Error("Expected lower data quality due to gaps and missing dimensions")
	}

	// Stability should still be good for metric1
	if metrics["stability"].(float64) <= 0.5 {
		t.Error("Expected reasonable stability despite gaps")
	}
}

func TestMultiDimHealthAssessment(t *testing.T) {
	dimensions := []string{"metric1", "metric2"}
	config := baseline.Config{
		UpdateInterval:  time.Second,
		MinSamples:      100,
		MediumTermAlpha: 0.1,
	}

	mdb, err := baseline.NewMultiDimBaseline(dimensions, config)
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Test initial health state
	t.Run("Initial Health", func(t *testing.T) {
		health := mdb.AssessHealth()
		if health.LearningProgress != 0 {
			t.Errorf("Expected 0 learning progress, got %.2f", health.LearningProgress)
		}
		if health.LearningPhase != "Initial" {
			t.Errorf("Expected Initial learning phase, got %s", health.LearningPhase)
		}
		if health.Coverage != 0.1 {
			t.Errorf("Expected 0.1 coverage, got %.2f", health.Coverage)
		}
	})

	// Add points with good coverage
	baseTime := time.Now()
	for i := 0; i < 50; i++ {
		point := baseline.MultiDimPoint{
			Values: map[string]float64{
				"metric1": float64(100 + i),
				"metric2": float64(200 + i),
			},
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
		}
		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point %d: %v", i, err)
		}
	}

	t.Run("Learning Progress", func(t *testing.T) {
		health := mdb.AssessHealth()
		expectedProgress := float64(50) / float64(config.MinSamples)
		if math.Abs(health.LearningProgress-expectedProgress) > 0.01 {
			t.Errorf("Expected %.2f learning progress, got %.2f", expectedProgress, health.LearningProgress)
		}
		if health.LearningPhase != "Initial" {
			t.Errorf("Expected Initial learning phase, got %s", health.LearningPhase)
		}
	})

	// Add points with missing dimensions
	for i := 0; i < 10; i++ {
		point := baseline.MultiDimPoint{
			Values: map[string]float64{
				"metric1": float64(150 + i),
			},
			Timestamp: baseTime.Add(time.Duration(60+i*10) * time.Second),
		}
		if err := mdb.AddPoint(point); err != nil {
			t.Errorf("Failed to add point %d: %v", i, err)
		}
	}

	t.Run("Coverage and Quality", func(t *testing.T) {
		health := mdb.AssessHealth()
		if health.Coverage >= 1.0 {
			t.Error("Expected coverage less than 1.0 due to missing dimensions")
		}
		if health.Confidence >= 0.9 {
			t.Error("Expected confidence less than 0.9 due to gaps and missing dimensions")
		}
	})

	t.Run("Health Status", func(t *testing.T) {
		status := mdb.GetStatus()
		if status.Status != "Degraded" {
			t.Errorf("Expected Degraded status, got %s", status.Status)
		}
		if len(status.Issues) == 0 {
			t.Error("Expected non-empty issues list")
		}
		if !strings.Contains(status.Issues[0], "coverage") {
			t.Error("Expected coverage issue in issues list")
		}
	})

	t.Run("Dimension Coverage", func(t *testing.T) {
		health := mdb.AssessHealth()
		if coverage, exists := health.ProtocolCoverage["metric1"]; !exists || coverage < 0.9 {
			t.Errorf("Expected high coverage for metric1, got %.2f", coverage)
		}
		if coverage, exists := health.ProtocolCoverage["metric2"]; !exists || coverage > 0.9 {
			t.Errorf("Expected low coverage for metric2, got %.2f", coverage)
		}
	})
}

// comparePoints compares two MultiDimPoint slices by value
func comparePoints(a, b []baseline.MultiDimPoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(a[i].Values, b[i].Values) ||
			!a[i].Timestamp.Equal(b[i].Timestamp) {
			return false
		}
	}
	return true
}

// compareDimensions compares two DimensionStats maps by value
func compareDimensions(a, b map[string]*baseline.DimensionStats) bool {
	if len(a) != len(b) {
		log.Printf("Dimension count mismatch: %d vs %d", len(a), len(b))
		return false
	}
	for k, v1 := range a {
		v2, ok := b[k]
		if !ok {
			log.Printf("Dimension %s missing in second map", k)
			return false
		}
		if v1.Name != v2.Name {
			log.Printf("Name mismatch for %s: %s vs %s", k, v1.Name, v2.Name)
			return false
		}
		if v1.Weight != v2.Weight {
			log.Printf("Weight mismatch for %s: %f vs %f", k, v1.Weight, v2.Weight)
			return false
		}
		if v1.LastValue != v2.LastValue {
			log.Printf("LastValue mismatch for %s: %f vs %f", k, v1.LastValue, v2.LastValue)
			return false
		}
		// Compare bounds, handling empty slices
		if len(v1.Bounds) != len(v2.Bounds) {
			log.Printf("Bounds length mismatch for %s: %d vs %d", k, len(v1.Bounds), len(v2.Bounds))
			return false
		}
		for i := range v1.Bounds {
			if v1.Bounds[i] != v2.Bounds[i] {
				log.Printf("Bounds value mismatch for %s at index %d: %f vs %f", k, i, v1.Bounds[i], v2.Bounds[i])
				return false
			}
		}
		if v1.Variance.GetMean() != v2.Variance.GetMean() {
			log.Printf("Mean mismatch for %s: %f vs %f", k, v1.Variance.GetMean(), v2.Variance.GetMean())
			return false
		}
		if v1.Variance.GetVariance() != v2.Variance.GetVariance() {
			log.Printf("Variance mismatch for %s: %f vs %f", k, v1.Variance.GetVariance(), v2.Variance.GetVariance())
			return false
		}
		if v1.EWMA.GetValue() != v2.EWMA.GetValue() {
			log.Printf("EWMA mismatch for %s: %f vs %f", k, v1.EWMA.GetValue(), v2.EWMA.GetValue())
			return false
		}
	}
	return true
}

// compareCorrelations compares two CorrelationTracker maps by value
func compareCorrelations(a, b map[string]*baseline.CorrelationTracker) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v1 := range a {
		v2, ok := b[k]
		if !ok {
			return false
		}
		if math.Abs(v1.GetCorrelation()-v2.GetCorrelation()) > 0.0001 {
			return false
		}
	}
	return true
}

// compareSeasonality compares two SeasonalityDetector instances by value
func compareSeasonality(a, b *baseline.SeasonalityDetector) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	if len(a.Patterns) != len(b.Patterns) {
		return false
	}
	// Compare scores for a few test values across all dimensions
	testTimes := []time.Time{
		time.Now(),
		time.Now().Add(time.Hour),
		time.Now().Add(24 * time.Hour),
	}
	testDims := []string{"metric1", "metric2"}
	for _, dim := range testDims {
		for _, t := range testTimes {
			score1 := a.GetSeasonalScore(dim, 100.0, t)
			score2 := b.GetSeasonalScore(dim, 100.0, t)
			if math.Abs(score1-score2) > 0.0001 {
				return false
			}
		}
	}
	return true
}

// compareQuality compares two Quality structs by value
func compareQuality(a, b struct {
	Coverage    float64
	Stability   float64
	LastUpdate  time.Time
	DataQuality float64
}) bool {
	return math.Abs(a.Coverage-b.Coverage) < 0.0001 &&
		math.Abs(a.Stability-b.Stability) < 0.0001 &&
		math.Abs(a.DataQuality-b.DataQuality) < 0.0001 &&
		a.LastUpdate.Equal(b.LastUpdate)
}

// TestMultiDimPersistence tests saving and loading baseline state
func TestMultiDimPersistence(t *testing.T) {
	// Create temp directory for test files
	tempDir, err := os.MkdirTemp("", "baseline_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create baseline with test data
	dims := []string{"metric1", "metric2"}
	mdb, err := baseline.NewMultiDimBaseline(dims, baseline.Config{
		InitialLearningPeriod: 24 * time.Hour,
		UpdateInterval:        time.Second,
		MinSamples:            10,
		ShortTermAlpha:        0.3,
		MediumTermAlpha:       0.1,
		LongTermAlpha:         0.05,
		AnomalyThreshold:      3.0,
		PersistenceEnabled:    true,
		PersistencePath:       tempDir,
		CheckpointInterval:    time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Add some test points
	now := time.Now()
	for i := 0; i < 20; i++ {
		point := baseline.MultiDimPoint{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Values: map[string]float64{
				"metric1": float64(i),
				"metric2": float64(i * 2),
			},
		}
		mdb.AddPoint(point)
	}

	// Add some points with missing dimensions
	for i := 20; i < 30; i++ {
		point := baseline.MultiDimPoint{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Values: map[string]float64{
				"metric1": float64(i),
			},
		}
		mdb.AddPoint(point)
	}

	// Save state
	savePath := filepath.Join(tempDir, "baseline.state")
	if err := mdb.Save(savePath); err != nil {
		t.Fatalf("Failed to save state: %v", err)
	}

	// Create new baseline and load state
	loadedMdb, err := baseline.NewMultiDimBaseline(dims, baseline.Config{
		InitialLearningPeriod: 24 * time.Hour,
		UpdateInterval:        time.Second,
		MinSamples:            10,
		ShortTermAlpha:        0.3,
		MediumTermAlpha:       0.1,
		LongTermAlpha:         0.05,
		AnomalyThreshold:      3.0,
		PersistenceEnabled:    true,
		PersistencePath:       tempDir,
		CheckpointInterval:    time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}
	if err := loadedMdb.Load(savePath); err != nil {
		t.Fatalf("Failed to load state: %v", err)
	}

	// Verify loaded state matches original
	if !comparePoints(mdb.Points, loadedMdb.Points) {
		t.Error("Points do not match after load")
	}
	if !compareDimensions(mdb.Dimensions, loadedMdb.Dimensions) {
		t.Error("Dimensions do not match after load")
	}
	if !compareCorrelations(mdb.DimensionCorrelations, loadedMdb.DimensionCorrelations) {
		t.Error("Dimension correlations do not match after load")
	}
	if !compareSeasonality(mdb.SeasonalityDetector, loadedMdb.SeasonalityDetector) {
		t.Error("Seasonality detector does not match after load")
	}
	if !reflect.DeepEqual(mdb.DimensionHistory, loadedMdb.DimensionHistory) {
		t.Error("Dimension history does not match after load")
	}
	if !compareQuality(mdb.Quality, loadedMdb.Quality) {
		t.Error("Quality metrics do not match after load")
	}
	if !reflect.DeepEqual(mdb.Config, loadedMdb.Config) {
		t.Error("Config does not match after load")
	}

	// Test error cases
	t.Run("NonexistentFile", func(t *testing.T) {
		err := mdb.Load(filepath.Join(tempDir, "nonexistent.state"))
		if err == nil {
			t.Error("Expected error loading nonexistent file")
		}
	})

	t.Run("InvalidDirectory", func(t *testing.T) {
		err := mdb.Save("/invalid/path/baseline.state")
		if err == nil {
			t.Error("Expected error saving to invalid directory")
		}
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Add(-1)
				point := baseline.MultiDimPoint{
					Timestamp: now.Add(time.Duration(i) * time.Second),
					Values: map[string]float64{
						"metric1": float64(i),
						"metric2": float64(i * 2),
					},
				}
				mdb.AddPoint(point)
				savePath := filepath.Join(tempDir, fmt.Sprintf("baseline_%d.state", i))
				err := mdb.Save(savePath)
				if err != nil {
					t.Errorf("Failed concurrent save: %v", err)
				}
			}(i)
		}
		wg.Wait()
	})

	t.Run("StateValidation", func(t *testing.T) {
		// Create invalid state file
		invalidPath := filepath.Join(tempDir, "invalid.state")
		file, err := os.Create(invalidPath)
		if err != nil {
			t.Fatalf("Failed to create invalid state file: %v", err)
		}
		defer file.Close()

		encoder := gob.NewEncoder(file)
		err = encoder.Encode(struct{}{})
		if err != nil {
			t.Fatalf("Failed to encode invalid state: %v", err)
		}

		// Try to load invalid state
		err = mdb.Load(invalidPath)
		if err == nil {
			t.Error("Expected error loading invalid state")
		}
	})
}
