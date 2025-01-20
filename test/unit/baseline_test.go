package unit

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/objones25/go-network-security-agent/pkg/capture"
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

func TestBaselinePersistence(t *testing.T) {
	t.Run("Save and Load", func(t *testing.T) {
		// Create temp directory for test
		tempDir := t.TempDir()

		// Create manager with persistence enabled
		config := baseline.DefaultConfig()
		config.PersistencePath = tempDir
		config.PersistenceEnabled = true
		config.CheckpointInterval = time.Second

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		// Start the manager
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err = manager.Start(ctx)
		require.NoError(t, err)

		// Add some test data
		for i := 0; i < 100; i++ {
			snapshot := capture.StatsSnapshot{
				TotalPackets: uint64(100 + i),
				TotalBytes:   uint64(1000 + i*10),
				PacketsByProtocol: map[string]uint64{
					"TCP": uint64(80 + i),
					"UDP": uint64(20),
				},
				BytesByProtocol: map[string]uint64{
					"TCP": uint64(800 + i*10),
					"UDP": uint64(200),
				},
				LastUpdated: time.Now(),
			}
			manager.AddMetrics(snapshot)
		}

		// Wait for metrics to be processed
		time.Sleep(500 * time.Millisecond)

		// Log original stats before saving
		for _, proto := range []string{"TCP", "UDP"} {
			if stats, ok := manager.GetProtocolStats(proto); ok {
				t.Logf("Before save - Protocol %s: short=%v, medium=%v, long=%v",
					proto,
					stats.ShortTermVolume.GetValue(),
					stats.MediumTermVolume.GetValue(),
					stats.LongTermVolume.GetValue())
			} else {
				t.Logf("Before save - Protocol %s: not found", proto)
			}
		}

		// Save state
		err = manager.Save()
		require.NoError(t, err)

		// Create new manager and load state
		newManager, err := baseline.NewManager(config)
		require.NoError(t, err)
		err = newManager.Load()
		require.NoError(t, err)

		// Log loaded stats
		for _, proto := range []string{"TCP", "UDP"} {
			if stats, ok := newManager.GetProtocolStats(proto); ok {
				t.Logf("After load - Protocol %s: short=%v, medium=%v, long=%v",
					proto,
					stats.ShortTermVolume.GetValue(),
					stats.MediumTermVolume.GetValue(),
					stats.LongTermVolume.GetValue())
			} else {
				t.Logf("After load - Protocol %s: not found", proto)
			}
		}

		// Verify loaded state matches original
		assert.Equal(t, manager.IsInitialized(), newManager.IsInitialized())

		// Check protocol stats
		protocols := []string{"TCP", "UDP"}
		for _, proto := range protocols {
			origStats, ok1 := manager.GetProtocolStats(proto)
			newStats, ok2 := newManager.GetProtocolStats(proto)
			t.Logf("Protocol %s: ok1=%v, ok2=%v", proto, ok1, ok2)
			if ok1 && ok2 {
				t.Logf("Protocol %s stats: orig=%v, new=%v", proto,
					origStats.ShortTermVolume.GetValue(),
					newStats.ShortTermVolume.GetValue())
			}
			require.True(t, ok1, "Original stats not found for protocol %s", proto)
			require.True(t, ok2, "Loaded stats not found for protocol %s", proto)
			assert.InDelta(t, origStats.ShortTermVolume.GetValue(), newStats.ShortTermVolume.GetValue(), 0.0001)
			assert.InDelta(t, origStats.MediumTermVolume.GetValue(), newStats.MediumTermVolume.GetValue(), 0.0001)
			assert.InDelta(t, origStats.LongTermVolume.GetValue(), newStats.LongTermVolume.GetValue(), 0.0001)
		}
	})

	t.Run("Persistence Disabled", func(t *testing.T) {
		config := baseline.DefaultConfig()
		config.PersistenceEnabled = false

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		// Save and load should be no-ops
		err = manager.Save()
		assert.NoError(t, err)
		err = manager.Load()
		assert.NoError(t, err)
	})

	t.Run("Invalid Directory", func(t *testing.T) {
		config := baseline.DefaultConfig()
		config.PersistenceEnabled = true
		config.PersistencePath = "/nonexistent/directory/that/should/not/exist"

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		// Save should fail but not panic
		err = manager.Save()
		assert.Error(t, err)
	})

	t.Run("Automatic Checkpointing", func(t *testing.T) {
		tempDir := t.TempDir()

		config := baseline.DefaultConfig()
		config.PersistencePath = tempDir
		config.PersistenceEnabled = true
		config.CheckpointInterval = 100 * time.Millisecond

		// Create persistence directory
		err := os.MkdirAll(tempDir, 0755)
		require.NoError(t, err)

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err = manager.Start(ctx)
		require.NoError(t, err)

		// Add metrics
		for i := 0; i < 10; i++ {
			snapshot := capture.StatsSnapshot{
				TotalPackets: uint64(100 + i),
				TotalBytes:   uint64(1000 + i*10),
				PacketsByProtocol: map[string]uint64{
					"TCP": uint64(80 + i),
				},
				LastUpdated: time.Now(),
			}
			manager.AddMetrics(snapshot)
			time.Sleep(20 * time.Millisecond)
		}

		// Wait for checkpoints
		time.Sleep(300 * time.Millisecond)

		// Verify state file exists
		_, err = os.Stat(filepath.Join(tempDir, "baseline.state"))
		assert.NoError(t, err)
	})

	t.Run("Shutdown_Persistence", func(t *testing.T) {
		tempDir := t.TempDir()

		config := baseline.DefaultConfig()
		config.PersistencePath = tempDir
		config.PersistenceEnabled = true

		// Create persistence directory
		err := os.MkdirAll(tempDir, 0755)
		require.NoError(t, err)

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		err = manager.Start(ctx)
		require.NoError(t, err)

		// Add some metrics
		snapshot := capture.StatsSnapshot{
			TotalPackets: 100,
			TotalBytes:   1000,
			PacketsByProtocol: map[string]uint64{
				"TCP": 80,
			},
			LastUpdated: time.Now(),
		}
		manager.AddMetrics(snapshot)

		// Wait for metrics to be processed
		time.Sleep(500 * time.Millisecond)

		// Trigger shutdown
		cancel()
		time.Sleep(100 * time.Millisecond)

		// Verify state was saved
		_, err = os.Stat(filepath.Join(tempDir, "baseline.state"))
		assert.NoError(t, err)

		// Load state in new manager
		newManager, err := baseline.NewManager(config)
		require.NoError(t, err)
		err = newManager.Load()
		require.NoError(t, err)

		// Verify state was preserved
		origStats, ok1 := manager.GetProtocolStats("TCP")
		newStats, ok2 := newManager.GetProtocolStats("TCP")
		require.True(t, ok1)
		require.True(t, ok2)
		assert.InDelta(t, origStats.ShortTermVolume.GetValue(), newStats.ShortTermVolume.GetValue(), 0.0001)
	})
}

func TestProtocolStats(t *testing.T) {
	t.Run("Protocol Stats Creation", func(t *testing.T) {
		config := baseline.DefaultConfig()
		stats := baseline.NewProtocolStats(config)

		assert.NotNil(t, stats.ShortTermVolume)
		assert.NotNil(t, stats.ShortTermBytes)
		assert.NotNil(t, stats.PacketVariance)
		assert.NotNil(t, stats.ByteVariance)
		assert.NotNil(t, stats.ConnectionCount)
		assert.Equal(t, config.AnomalyThreshold, stats.PacketThreshold)
	})

	t.Run("Stats Update", func(t *testing.T) {
		config := baseline.DefaultConfig()
		stats := baseline.NewProtocolStats(config)

		// Add some test data
		now := time.Now()
		stats.UpdateStats(100, 1000, now)
		stats.UpdateStats(150, 1500, now.Add(time.Second))
		stats.UpdateStats(200, 2000, now.Add(2*time.Second))

		// Check volume metrics
		assert.Greater(t, stats.ShortTermVolume.GetValue(), 0.0)
		assert.Greater(t, stats.MediumTermVolume.GetValue(), 0.0)
		assert.Greater(t, stats.LongTermVolume.GetValue(), 0.0)

		// Check byte metrics
		assert.Greater(t, stats.ShortTermBytes.GetValue(), 0.0)
		assert.Greater(t, stats.MediumTermBytes.GetValue(), 0.0)
		assert.Greater(t, stats.LongTermBytes.GetValue(), 0.0)

		// Check average packet size
		avgPacketSize := stats.AveragePacketSize.GetValue()
		assert.InDelta(t, 10.0, avgPacketSize, 1.0) // Each packet is ~10 bytes
	})

	t.Run("Anomaly Detection", func(t *testing.T) {
		config := baseline.DefaultConfig()
		config.AnomalyThreshold = 2.0 // Lower threshold for testing
		stats := baseline.NewProtocolStats(config)

		// Establish baseline
		now := time.Now()
		for i := 0; i < 10; i++ {
			stats.UpdateStats(100, 1000, now.Add(time.Duration(i)*time.Second))
		}

		// Test normal traffic
		assert.False(t, stats.IsAnomaly(110, 1100)) // Within normal range

		// Test anomalous traffic
		assert.True(t, stats.IsAnomaly(1000, 10000)) // 10x normal
	})

	t.Run("Stats Retrieval", func(t *testing.T) {
		config := baseline.DefaultConfig()
		stats := baseline.NewProtocolStats(config)

		// Add some data
		now := time.Now()
		stats.UpdateStats(100, 1000, now)

		// Get stats
		metrics := stats.GetStats()
		assert.NotZero(t, metrics["short_term_volume"])
		assert.NotZero(t, metrics["short_term_bytes"])
		assert.NotZero(t, metrics["avg_packet_size"])
	})
}

// TestCircularBuffer tests the circular buffer implementation
func TestCircularBuffer(t *testing.T) {
	t.Run("Basic Operations", func(t *testing.T) {
		cb := baseline.NewCircularBuffer(5)

		// Test initial state
		if cb.Size != 0 || cb.IsFull {
			t.Errorf("New buffer should be empty: Size=%d, IsFull=%v", cb.Size, cb.IsFull)
		}

		// Add points and verify
		now := time.Now()
		points := []baseline.DataPoint{
			{Timestamp: now, PacketCount: 1, ByteCount: 100},
			{Timestamp: now.Add(time.Second), PacketCount: 2, ByteCount: 200},
			{Timestamp: now.Add(2 * time.Second), PacketCount: 3, ByteCount: 300},
		}

		for _, p := range points {
			cb.Add(p)
		}

		if cb.Size != 3 {
			t.Errorf("Buffer Size should be 3, got %d", cb.Size)
		}

		// Verify points retrieval
		retrieved := cb.GetPoints(now.Add(-time.Second))
		if len(retrieved) != 3 {
			t.Errorf("Expected 3 points, got %d", len(retrieved))
		}

		// Verify point values
		for i, p := range retrieved {
			if p.PacketCount != uint64(i+1) {
				t.Errorf("Point %d: expected PacketCount %d, got %d", i, i+1, p.PacketCount)
			}
		}
	})

	t.Run("Buffer Overflow", func(t *testing.T) {
		cb := baseline.NewCircularBuffer(3)
		now := time.Now()

		// Add more points than capacity
		for i := 0; i < 5; i++ {
			cb.Add(baseline.DataPoint{
				Timestamp:   now.Add(time.Duration(i) * time.Second),
				PacketCount: uint64(i + 1),
				ByteCount:   uint64(i * 100),
			})
		}

		// Verify buffer maintains only latest 3 points
		points := cb.GetPoints(now.Add(-time.Hour))
		if len(points) != 3 {
			t.Errorf("Expected 3 points after overflow, got %d", len(points))
		}

		// Verify the correct points were kept (should be 3,4,5)
		for i, p := range points {
			expected := uint64(i + 3)
			if p.PacketCount != expected {
				t.Errorf("Point %d: expected PacketCount %d, got %d", i, expected, p.PacketCount)
			}
		}
	})

	t.Run("Time Window Filtering", func(t *testing.T) {
		cb := baseline.NewCircularBuffer(5)
		now := time.Now()

		// Add points at different times
		points := []baseline.DataPoint{
			{Timestamp: now.Add(-2 * time.Hour), PacketCount: 1},
			{Timestamp: now.Add(-1 * time.Hour), PacketCount: 2},
			{Timestamp: now, PacketCount: 3},
			{Timestamp: now.Add(time.Hour), PacketCount: 4},
		}

		for _, p := range points {
			cb.Add(p)
		}

		// Get points after a certain time
		retrieved := cb.GetPoints(now.Add(-30 * time.Minute))
		if len(retrieved) != 2 {
			t.Errorf("Expected 2 points within time window, got %d", len(retrieved))
		}

		if retrieved[0].PacketCount != 3 || retrieved[1].PacketCount != 4 {
			t.Errorf("Incorrect points retrieved: got %v", retrieved)
		}
	})
}

// TestDataPointPooling tests the DataPoint memory pool
func TestDataPointPooling(t *testing.T) {
	t.Run("Pool Reuse", func(t *testing.T) {
		// Get a point from the pool
		point1 := baseline.GetDataPoint()
		point1.PacketCount = 100
		point1.ByteCount = 1000
		point1.Timestamp = time.Now()

		// Put it back using the new Put method
		point1.Put()

		// Get another point
		point2 := baseline.GetDataPoint()

		// Verify we got a clean object (values should be zero)
		if point2.PacketCount != 0 || point2.ByteCount != 0 || !point2.Timestamp.IsZero() {
			t.Errorf("Pool should return clean objects, got PacketCount=%d, ByteCount=%d, Timestamp=%v",
				point2.PacketCount, point2.ByteCount, point2.Timestamp)
		}

		// Clean up
		point2.Put()
	})

	t.Run("Concurrent Pool Access", func(t *testing.T) {
		var wg sync.WaitGroup
		numGoroutines := 100
		pointsPerGoroutine := 1000

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < pointsPerGoroutine; j++ {
					point := baseline.GetDataPoint()
					point.PacketCount = uint64(j)
					point.ByteCount = uint64(j * 100)
					point.Timestamp = time.Now()
					point.Put() // Use new Put method
				}
			}()
		}

		wg.Wait()
	})
}

// BenchmarkCircularBuffer benchmarks the circular buffer operations
func BenchmarkCircularBuffer(b *testing.B) {
	b.Run("Sequential Add", func(b *testing.B) {
		cb := baseline.NewCircularBuffer(1000)
		now := time.Now()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cb.Add(baseline.DataPoint{
				Timestamp:   now.Add(time.Duration(i) * time.Second),
				PacketCount: uint64(i),
				ByteCount:   uint64(i * 100),
			})
		}
	})

	b.Run("Add and GetPoints", func(b *testing.B) {
		cb := baseline.NewCircularBuffer(1000)
		now := time.Now()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cb.Add(baseline.DataPoint{
				Timestamp:   now.Add(time.Duration(i) * time.Second),
				PacketCount: uint64(i),
				ByteCount:   uint64(i * 100),
			})

			if i%100 == 0 {
				cb.GetPoints(now)
			}
		}
	})
}

// BenchmarkTimeWindow benchmarks the TimeWindow operations with the new optimizations
func BenchmarkTimeWindow(b *testing.B) {
	b.Run("AddDataPoint", func(b *testing.B) {
		window := baseline.NewTimeWindow(time.Now(), time.Hour, 0.1)
		now := time.Now()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			window.AddDataPoint(baseline.DataPoint{
				Timestamp:   now.Add(time.Duration(i) * time.Second),
				PacketCount: uint64(i),
				ByteCount:   uint64(i * 100),
			})
		}
	})

	b.Run("GetStats", func(b *testing.B) {
		window := baseline.NewTimeWindow(time.Now(), time.Hour, 0.1)
		now := time.Now()

		// Add some initial data
		for i := 0; i < 1000; i++ {
			window.AddDataPoint(baseline.DataPoint{
				Timestamp:   now.Add(time.Duration(i) * time.Second),
				PacketCount: uint64(i),
				ByteCount:   uint64(i * 100),
			})
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			window.GetStats()
		}
	})

	b.Run("IsAnomaly", func(b *testing.B) {
		window := baseline.NewTimeWindow(time.Now(), time.Hour, 0.1)
		now := time.Now()

		// Add some initial data
		for i := 0; i < 1000; i++ {
			window.AddDataPoint(baseline.DataPoint{
				Timestamp:   now.Add(time.Duration(i) * time.Second),
				PacketCount: uint64(i),
				ByteCount:   uint64(i * 100),
			})
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			window.IsAnomaly(2.0)
		}
	})
}
