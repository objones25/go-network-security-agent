package unit

import (
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
