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
