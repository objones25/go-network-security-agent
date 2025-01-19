package unit

import (
	"math"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEWMA(t *testing.T) {
	t.Run("NewEWMA", func(t *testing.T) {
		// Test valid alpha
		ewma := baseline.NewEWMA(0.3)
		assert.NotNil(t, ewma)
		assert.Equal(t, 0.3, ewma.GetAlpha())

		// Test invalid alpha values
		ewma = baseline.NewEWMA(0)
		assert.Equal(t, 0.1, ewma.GetAlpha()) // Should default to 0.1

		ewma = baseline.NewEWMA(1.5)
		assert.Equal(t, 0.1, ewma.GetAlpha()) // Should default to 0.1
	})

	t.Run("Update", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)
		values := []float64{10, 20, 30, 40, 50}
		expected := 0.0

		for i, v := range values {
			ewma.Update(v)
			if i == 0 {
				expected = v
			} else {
				expected = 0.2*v + 0.8*expected
			}
			assert.InDelta(t, expected, ewma.GetValue(), 0.0001)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)
		ewma.Update(100)
		ewma.Update(200)
		assert.NotEqual(t, 0.0, ewma.GetValue())
		assert.NotEqual(t, 0, ewma.GetCount())

		ewma.Reset()
		assert.Equal(t, 0.0, ewma.GetValue())
		assert.Equal(t, 0, ewma.GetCount())
	})

	t.Run("GetCount", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)
		assert.Equal(t, 0, ewma.GetCount())

		for i := 1; i <= 5; i++ {
			ewma.Update(float64(i * 10))
			assert.Equal(t, i, ewma.GetCount())
		}
	})

	t.Run("GetConfidenceBounds", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)

		// Test with no data
		lower, upper := ewma.GetConfidenceBounds(0.95)
		assert.Equal(t, 0.0, lower)
		assert.Equal(t, 0.0, upper)

		// Add some data
		values := []float64{100, 110, 90, 105, 95}
		for _, v := range values {
			ewma.Update(v)
		}

		lower, upper = ewma.GetConfidenceBounds(0.95)
		value := ewma.GetValue()
		assert.Less(t, lower, value)
		assert.Greater(t, upper, value)
		assert.InDelta(t, value, (lower+upper)/2, 0.0001)

		// Test different confidence levels
		lower1, upper1 := ewma.GetConfidenceBounds(0.95)
		lower2, upper2 := ewma.GetConfidenceBounds(0.99)
		assert.Greater(t, upper2-lower2, upper1-lower1) // 99% interval should be wider
	})

	t.Run("Concurrent Access", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)
		done := make(chan bool)

		// Start multiple goroutines updating the EWMA
		for i := 0; i < 10; i++ {
			go func(val float64) {
				for j := 0; j < 100; j++ {
					ewma.Update(val)
					ewma.GetValue()
					ewma.GetConfidenceBounds(0.95)
				}
				done <- true
			}(float64(i * 10))
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify the count is correct
		assert.Equal(t, 1000, ewma.GetCount())
	})

	t.Run("Edge Cases", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)

		// Test with zero
		ewma.Update(0)
		assert.Equal(t, 0.0, ewma.GetValue())

		// Test with very large numbers
		ewma.Reset()
		ewma.Update(math.MaxFloat64 / 2)
		assert.False(t, math.IsInf(ewma.GetValue(), 1))

		// Test with very small numbers
		ewma.Reset()
		ewma.Update(math.SmallestNonzeroFloat64)
		assert.False(t, math.IsInf(ewma.GetValue(), -1))

		// Test with NaN
		ewma.Reset()
		ewma.Update(math.NaN())
		assert.False(t, math.IsNaN(ewma.GetValue()))
		assert.Equal(t, 0.0, ewma.GetValue()) // Should remain unchanged
	})

	t.Run("Stability", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)
		value := 100.0

		// Update with the same value multiple times
		for i := 0; i < 100; i++ {
			ewma.Update(value)
		}

		// The EWMA should converge to the input value
		assert.InDelta(t, value, ewma.GetValue(), 0.0001)

		// Confidence bounds should be tight around the value
		lower, upper := ewma.GetConfidenceBounds(0.95)
		assert.InDelta(t, value, lower, value*0.1)
		assert.InDelta(t, value, upper, value*0.1)
	})
}

func TestEWMABehavior(t *testing.T) {
	t.Run("Trend Detection", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.3)

		// Simulate increasing trend
		for i := 0; i < 10; i++ {
			ewma.Update(float64(i * 10))
		}

		// EWMA should follow the trend but lag behind
		assert.Greater(t, ewma.GetValue(), 0.0)
		assert.Less(t, ewma.GetValue(), 90.0) // Last value was 90

		// Reset and simulate decreasing trend
		ewma.Reset()
		for i := 10; i > 0; i-- {
			ewma.Update(float64(i * 10))
		}

		// EWMA should follow the downward trend but lag behind
		assert.Greater(t, ewma.GetValue(), 10.0) // Last value was 10
		assert.Less(t, ewma.GetValue(), 100.0)   // First value was 100
	})

	t.Run("Response to Outliers", func(t *testing.T) {
		ewma := baseline.NewEWMA(0.2)

		// Establish baseline
		for i := 0; i < 10; i++ {
			ewma.Update(100.0)
		}
		baseline := ewma.GetValue()

		// Introduce outlier
		ewma.Update(1000.0)
		spikeValue := ewma.GetValue()

		// Value should move towards outlier but not reach it
		assert.Greater(t, spikeValue, baseline)
		assert.Less(t, spikeValue, 1000.0)
		assert.InDelta(t, baseline+0.2*(1000.0-baseline), spikeValue, 0.0001)

		// Recovery after outlier
		ewma.Update(100.0)
		recoveryValue := ewma.GetValue()

		// Should move back towards baseline
		assert.Less(t, recoveryValue, spikeValue)
	})

	t.Run("Different Alpha Values", func(t *testing.T) {
		// Compare fast vs slow EWMA
		fastEWMA := baseline.NewEWMA(0.3) // Responds quickly to changes
		slowEWMA := baseline.NewEWMA(0.1) // Responds slowly to changes

		// Initialize both with same starting value
		initialValue := 100.0
		fastEWMA.Update(initialValue)
		slowEWMA.Update(initialValue)

		// Add a spike value
		spikeValue := 200.0
		fastEWMA.Update(spikeValue)
		slowEWMA.Update(spikeValue)

		// Fast EWMA should move more towards the spike
		fastDiff := math.Abs(spikeValue - fastEWMA.GetValue())
		slowDiff := math.Abs(spikeValue - slowEWMA.GetValue())
		assert.Less(t, fastDiff, slowDiff,
			"Fast EWMA should be closer to spike value than slow EWMA")
	})
}

func TestVarianceTracker(t *testing.T) {
	t.Run("Basic Statistics", func(t *testing.T) {
		t.Log("Starting Basic Statistics test")
		v := baseline.NewVarianceTracker()
		values := []float64{2, 4, 4, 4, 5, 5, 7, 9}

		t.Log("Adding values to variance tracker")
		for i, val := range values {
			t.Logf("Adding value %d: %v", i, val)
			v.Add(val)
		}

		t.Log("Getting final statistics")
		mean, stdDev, min, max := v.GetStats()
		t.Logf("Got stats: mean=%v, stdDev=%v, min=%v, max=%v", mean, stdDev, min, max)

		assert.InDelta(t, 5.0, mean, 0.0001)
		assert.InDelta(t, 2.138089935299395, stdDev, 0.0001)
		assert.Equal(t, 2.0, min)
		assert.Equal(t, 9.0, max)
		t.Log("Basic Statistics test completed")
	})

	t.Run("Anomaly Detection", func(t *testing.T) {
		v := baseline.NewVarianceTracker()

		// Add normal values
		for i := 0; i < 100; i++ {
			v.Add(100.0)
		}

		// Test normal value
		assert.False(t, v.IsAnomaly(105.0, 3.0))

		// Test anomalous value
		assert.True(t, v.IsAnomaly(200.0, 3.0))
	})

	t.Run("Confidence Interval", func(t *testing.T) {
		v := baseline.NewVarianceTracker()
		values := []float64{10, 12, 14, 16, 18}

		for _, val := range values {
			v.Add(val)
		}

		lower, upper := v.GetConfidenceInterval(0.95)
		mean := v.GetMean()
		assert.Less(t, lower, mean)
		assert.Greater(t, upper, mean)
	})
}

func TestTimeWindow(t *testing.T) {
	t.Run("Basic Window Operations", func(t *testing.T) {
		now := time.Now()
		w := baseline.NewTimeWindow(now, time.Hour, 0.2)

		// Add some data points
		points := []baseline.DataPoint{
			{Timestamp: now, PacketCount: 100, ByteCount: 1000},
			{Timestamp: now.Add(time.Minute), PacketCount: 150, ByteCount: 1500},
			{Timestamp: now.Add(2 * time.Minute), PacketCount: 200, ByteCount: 2000},
		}

		for _, p := range points {
			w.AddDataPoint(p)
		}

		// Check statistics
		packetRate, byteRate, variance := w.GetStats()
		assert.Greater(t, packetRate, 0.0)
		assert.Greater(t, byteRate, 0.0)
		assert.GreaterOrEqual(t, variance, 0.0)
	})

	t.Run("Window Pruning", func(t *testing.T) {
		now := time.Now()
		w := baseline.NewTimeWindow(now, time.Hour, 0.2)

		// Add old data points
		oldPoint := baseline.DataPoint{
			Timestamp:   now.Add(-2 * time.Hour),
			PacketCount: 100,
			ByteCount:   1000,
		}
		w.AddDataPoint(oldPoint)

		// Add new data point
		newPoint := baseline.DataPoint{
			Timestamp:   now,
			PacketCount: 200,
			ByteCount:   2000,
		}
		w.AddDataPoint(newPoint)

		// Get data points - should only contain the new point
		points := w.GetDataPoints()
		assert.Equal(t, 1, len(points))
		assert.Equal(t, uint64(200), points[0].PacketCount)
	})
}

func TestWindowManager(t *testing.T) {
	t.Run("Window Initialization", func(t *testing.T) {
		wm := baseline.NewWindowManager(0.2)
		now := time.Now()

		minute, hour, day, month := wm.GetWindowStats(now)
		assert.NotNil(t, minute)
		assert.NotNil(t, hour)
		assert.NotNil(t, day)
		assert.NotNil(t, month)
	})

	t.Run("Data Point Distribution", func(t *testing.T) {
		wm := baseline.NewWindowManager(0.2)
		now := time.Now()

		point := baseline.DataPoint{
			Timestamp:   now,
			PacketCount: 100,
			ByteCount:   1000,
		}

		wm.AddDataPoint(point)

		// Verify point was added to all relevant windows
		minute, hour, day, month := wm.GetWindowStats(now)
		packetRate, _, _ := minute.GetStats()
		assert.Greater(t, packetRate, 0.0)

		packetRate, _, _ = hour.GetStats()
		assert.Greater(t, packetRate, 0.0)

		packetRate, _, _ = day.GetStats()
		assert.Greater(t, packetRate, 0.0)

		packetRate, _, _ = month.GetStats()
		assert.Greater(t, packetRate, 0.0)
	})
}

func TestBaselineManager(t *testing.T) {
	t.Run("Configuration", func(t *testing.T) {
		config := baseline.DefaultConfig()
		assert.Equal(t, 24*time.Hour, config.InitialLearningPeriod)
		assert.Equal(t, time.Hour, config.UpdateInterval)
		assert.Equal(t, 1000, config.MinSamples)
		assert.Equal(t, 0.3, config.ShortTermAlpha)
		assert.Equal(t, 0.1, config.MediumTermAlpha)
		assert.Equal(t, 0.05, config.LongTermAlpha)
		assert.Equal(t, 3.0, config.AnomalyThreshold)
	})

	t.Run("Manager Creation", func(t *testing.T) {
		config := baseline.DefaultConfig()
		manager, err := baseline.NewManager(config)
		require.NoError(t, err)
		assert.NotNil(t, manager)
		assert.False(t, manager.IsInitialized())
	})

	t.Run("Invalid Configuration", func(t *testing.T) {
		invalidConfigs := []baseline.Config{
			{InitialLearningPeriod: -time.Hour},
			{InitialLearningPeriod: time.Hour, UpdateInterval: -time.Minute},
			{InitialLearningPeriod: time.Hour, UpdateInterval: time.Minute, MinSamples: -1},
		}

		for _, config := range invalidConfigs {
			manager, err := baseline.NewManager(config)
			assert.Error(t, err)
			assert.Nil(t, manager)
		}
	})
}
