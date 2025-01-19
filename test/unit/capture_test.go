package unit

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPCAPEngine(t *testing.T) {
	tests := []struct {
		name        string
		config      capture.Config
		expectError bool
	}{
		{
			name: "Valid Configuration",
			config: capture.Config{
				Interface:   "lo0",
				Promiscuous: true,
				SnapshotLen: 65535,
				Timeout:     time.Second,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := capture.NewPCAPEngine(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, engine)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, engine)
			}
		})
	}
}

func TestPCAPEngineLifecycle(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)
	assert.NotNil(t, engine)

	// Test Start
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = engine.Start(ctx)
	assert.NoError(t, err)

	// Ensure packet channel is created
	packetChan := engine.Packets()
	assert.NotNil(t, packetChan)

	// Test Stop
	err = engine.Stop()
	assert.NoError(t, err)

	// Verify channel is closed after stop
	_, ok := <-packetChan
	assert.False(t, ok, "Packet channel should be closed after stopping")
}

func TestPacketProcessing(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = engine.Start(ctx)
	assert.NoError(t, err)
	defer engine.Stop()

	// Test packet processing
	packetChan := engine.Packets()
	assert.NotNil(t, packetChan)

	// Generate some local traffic (you might need to adjust this based on your needs)
	go func() {
		// Ping localhost to generate some traffic
		_, _ = exec.Command("ping", "-c", "3", "127.0.0.1").Output()
	}()

	// Wait for some packets
	timeout := time.After(3 * time.Second)
	packetCount := 0

	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			assert.NotNil(t, packet.Data)
			assert.NotEmpty(t, packet.Timestamp)
			assert.NotZero(t, packet.Length)
			packetCount++
			if packetCount >= 3 {
				return
			}
		case <-timeout:
			t.Log("Received", packetCount, "packets")
			return
		}
	}
}

// TestRateLimiting tests the rate limiting functionality
func TestRateLimiting(t *testing.T) {
	config := capture.Config{
		Interface:  "lo0",
		RateLimit:  100, // 100 packets per second
		SampleRate: 1.0, // Process all packets
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)

	start := time.Now()
	processed := 0
	total := 200 // Total packets to process

	// Process packets with consistent timing
	for i := 0; i < total; i++ {
		// Simulate packet arrival every 1ms
		time.Sleep(time.Millisecond)
		if engine.ShouldProcessPacket() {
			processed++
		}
	}

	duration := time.Since(start)
	rate := float64(processed) / duration.Seconds()

	t.Logf("Processed %d/%d packets in %v (%.2f packets/sec)",
		processed, total, duration, rate)

	// Allow for some margin of error (10%)
	maxRate := float64(config.RateLimit) * 1.1
	minRate := float64(config.RateLimit) * 0.9
	assert.True(t, rate >= minRate && rate <= maxRate,
		"Rate should be between %.2f and %.2f packets/sec, got %.2f",
		minRate, maxRate, rate)
}

// TestSampling tests the packet sampling functionality
func TestSampling(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
		expected   float64
		tolerance  float64
	}{
		{"Full_Sampling", 1.0, 1.0, 0.1},
		{"Half_Sampling", 0.5, 0.5, 0.1},
		{"Quarter_Sampling", 0.25, 0.25, 0.1},
		{"No_Sampling", 0.0, 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := capture.Config{
				Interface:  "lo0",
				BPFFilter:  "",
				SampleRate: tt.sampleRate,
			}

			engine, err := capture.NewPCAPEngine(config)
			require.NoError(t, err)

			processed := 0
			total := 10000

			for i := 0; i < total; i++ {
				if engine.ShouldProcessPacket() {
					processed++
				}
			}

			actualRate := float64(processed) / float64(total)
			t.Logf("Sample rate: %.2f, Processed %d/%d packets (%.2f%%)",
				tt.sampleRate, processed, total, actualRate*100)

			if tt.sampleRate == 0.0 {
				assert.Equal(t, 0, processed, "No packets should be processed with 0.0 sample rate")
			} else {
				assert.InDelta(t, tt.expected, actualRate, tt.tolerance,
					"Sample rate should be within tolerance")
			}
		})
	}
}

// TestCombinedRateLimitingAndSampling tests both rate limiting and sampling together
func TestCombinedRateLimitingAndSampling(t *testing.T) {
	config := capture.Config{
		Interface:  "lo0",
		BPFFilter:  "",
		SampleRate: 0.5,
		RateLimit:  100,
	}

	engine, err := capture.NewPCAPEngine(config)
	require.NoError(t, err)

	processed := 0
	total := 400

	start := time.Now()
	for i := 0; i < total; i++ {
		if engine.ShouldProcessPacket() {
			processed++
		}
		// Simulate consistent packet arrival every 2ms
		time.Sleep(2 * time.Millisecond)
	}
	elapsed := time.Since(start)

	rate := float64(processed) / elapsed.Seconds()
	t.Logf("Processed %d/%d packets in %v (%.2f packets/sec)",
		processed, total, elapsed, rate)

	// With 50% sampling and 100 pps rate limit, expect ~50 pps
	// Allow 20% margin of error
	assert.True(t, rate >= 40 && rate <= 60,
		"Rate should be between 40.00 and 60.00 packets/sec, got %.2f", rate)
}

// TestAdaptiveBatchSizing verifies that batch sizes adjust correctly based on performance metrics
func TestAdaptiveBatchSizing(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		BatchSize:   100,
		NumWorkers:  2,
		SampleRate:  1.0,
		RateLimit:   1000,
		StatsPeriod: time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	require.NoError(t, err)

	// Set last adjustment far in the past
	engine.SetLastAdjustmentTime(time.Now().Add(-3 * time.Second))

	// Record initial batch size
	initialSize := engine.GetCurrentBatchSize()

	// Test high latency scenario
	for i := 0; i < 3; i++ {
		engine.Stats().ProcessingLatency = 100 * time.Millisecond
		engine.Stats().ChannelBacklog = 500
		engine.SetLastAdjustmentTime(time.Now().Add(-3 * time.Second))
		engine.AdjustBatchSize()

		newSize := engine.GetCurrentBatchSize()
		assert.Less(t, newSize, initialSize,
			"Batch size should decrease after adjustment %d", i+1)
		initialSize = newSize
	}

	// Test low utilization scenario
	engine.Stats().ProcessingLatency = time.Millisecond
	engine.Stats().ChannelBacklog = 0
	engine.Stats().WorkerUtilization = []float64{0.1, 0.1}
	engine.SetLastAdjustmentTime(time.Now().Add(-3 * time.Second))

	initialSize = engine.GetCurrentBatchSize()
	engine.AdjustBatchSize()

	newSize := engine.GetCurrentBatchSize()
	assert.Greater(t, newSize, initialSize,
		"Batch size should increase under low utilization")
	assert.Less(t, newSize, initialSize*2,
		"Batch size increase should be gradual")
}

// TestMetricsCollection verifies that performance metrics are collected correctly
func TestMetricsCollection(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		BatchSize:   100,
		NumWorkers:  2,
		SampleRate:  1.0,
		RateLimit:   1000,
		StatsPeriod: time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	require.NoError(t, err)

	// Simulate processing metrics
	start := time.Now().Add(-time.Second) // Set start time 1 second ago
	engine.UpdateMetrics(start, 100, 50, 0)

	metrics := engine.GetMetrics()
	require.NotZero(t, metrics["processing_latency_ns"])
	require.NotZero(t, metrics["batch_latency_ns"])
	require.Equal(t, 100, metrics["avg_batch_size"])
	require.Len(t, metrics["worker_utilization"].([]float64), 2)

	// Verify worker utilization calculation
	utilization := metrics["worker_utilization"].([]float64)[0]
	require.InDelta(t, 1.0, utilization, 0.1) // Should be close to 100% (1 second active time)
}

// TestMetricsReset verifies that metrics are properly reset
func TestMetricsReset(t *testing.T) {
	config := capture.Config{
		Interface:  "lo0",
		BatchSize:  100,
		NumWorkers: 2,
	}

	engine, err := capture.NewPCAPEngine(config)
	require.NoError(t, err)

	// Update some metrics
	engine.UpdateMetrics(time.Now().Add(-time.Second), 100, 50, 0)

	// Reset stats
	engine.ResetStats()

	metrics := engine.GetMetrics()
	assert.Equal(t, int64(0), metrics["processing_latency_ns"])
	assert.Equal(t, int64(0), metrics["batch_latency_ns"])
	assert.Equal(t, 0, metrics["channel_backlog"])

	for _, util := range metrics["worker_utilization"].([]float64) {
		assert.Equal(t, float64(0), util)
	}
}

// TestMemoryPooling verifies that packet batch memory is properly pooled and reused
func TestMemoryPooling(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		BatchSize:   100,
		NumWorkers:  2,
		SampleRate:  1.0,
		RateLimit:   1000,
		StatsPeriod: time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	require.NoError(t, err)

	// Get a batch from the pool
	batch1 := engine.GetBatchFromPool()
	require.NotNil(t, batch1)
	require.Equal(t, 0, len(*batch1))
	require.Equal(t, config.BatchSize*2, cap(*batch1)) // Should have double capacity for growth

	// Return batch to pool
	engine.ReturnBatchToPool(batch1)

	// Get another batch - should be the same underlying array
	batch2 := engine.GetBatchFromPool()
	require.Equal(t, cap(*batch1), cap(*batch2))
}
