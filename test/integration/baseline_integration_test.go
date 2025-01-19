package integration

import (
	"context"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaselineLearning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Learning Period", func(t *testing.T) {
		// Create baseline manager with short learning period for testing
		config := baseline.DefaultConfig()
		config.InitialLearningPeriod = 2 * time.Second
		config.UpdateInterval = 500 * time.Millisecond
		config.MinSamples = 10

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = manager.Start(ctx)
		require.NoError(t, err)
		defer manager.Stop()

		// Add metrics during learning period
		for i := 0; i < 20; i++ {
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
			time.Sleep(100 * time.Millisecond)
		}

		// Wait for learning period to complete
		time.Sleep(2 * time.Second)

		// Verify baseline is initialized
		assert.True(t, manager.IsInitialized())

		// Check protocol stats
		tcpStats, ok := manager.GetProtocolStats("TCP")
		require.True(t, ok)
		assert.Greater(t, tcpStats.ShortTermVolume.GetValue(), 0.0)
		assert.Greater(t, tcpStats.MediumTermVolume.GetValue(), 0.0)
		assert.Greater(t, tcpStats.LongTermVolume.GetValue(), 0.0)
	})

	t.Run("Anomaly Detection", func(t *testing.T) {
		config := baseline.DefaultConfig()
		config.InitialLearningPeriod = 2 * time.Second
		config.UpdateInterval = 500 * time.Millisecond
		config.MinSamples = 10
		config.AnomalyThreshold = 2.0 // Lower threshold for testing
		config.ShortTermAlpha = 0.5   // Increase alpha for faster response to changes

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = manager.Start(ctx)
		require.NoError(t, err)
		defer manager.Stop()

		// Establish baseline with normal traffic
		t.Log("Establishing baseline with normal traffic")
		for i := 0; i < 10; i++ {
			snapshot := capture.StatsSnapshot{
				TotalPackets: 100,
				TotalBytes:   1000,
				PacketsByProtocol: map[string]uint64{
					"TCP": 80,
					"UDP": 20,
				},
				BytesByProtocol: map[string]uint64{
					"TCP": 800,
					"UDP": 200,
				},
				LastUpdated: time.Now(),
			}
			manager.AddMetrics(snapshot)
			time.Sleep(100 * time.Millisecond)
		}

		// Wait for learning period
		t.Log("Waiting for learning period")
		time.Sleep(2 * time.Second)

		// Verify baseline is established
		assert.True(t, manager.IsInitialized())

		// Get TCP stats before anomaly
		tcpStats, ok := manager.GetProtocolStats("TCP")
		require.True(t, ok)
		normalValue := tcpStats.ShortTermVolume.GetValue()
		t.Logf("Normal value: %v", normalValue)

		// Introduce anomalous traffic
		t.Log("Introducing anomalous traffic")
		snapshot := capture.StatsSnapshot{
			TotalPackets: 1000, // 10x normal
			TotalBytes:   10000,
			PacketsByProtocol: map[string]uint64{
				"TCP": 800, // 10x normal
				"UDP": 200,
			},
			BytesByProtocol: map[string]uint64{
				"TCP": 8000,
				"UDP": 2000,
			},
			LastUpdated: time.Now(),
		}
		manager.AddMetrics(snapshot)

		// Wait for metrics to be processed
		time.Sleep(500 * time.Millisecond)

		// Verify anomaly is detected
		tcpStats, ok = manager.GetProtocolStats("TCP")
		require.True(t, ok)
		anomalyValue := tcpStats.ShortTermVolume.GetValue()
		t.Logf("Anomaly value: %v (expecting > %v)", anomalyValue, normalValue*1.5)
		assert.Greater(t, anomalyValue, normalValue*1.5) // Should show significant increase
	})

	t.Run("Time-Based Patterns", func(t *testing.T) {
		config := baseline.DefaultConfig()
		config.InitialLearningPeriod = 2 * time.Second
		config.UpdateInterval = 500 * time.Millisecond
		config.MinSamples = 10

		manager, err := baseline.NewManager(config)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = manager.Start(ctx)
		require.NoError(t, err)
		defer manager.Stop()

		// Simulate different traffic patterns for different hours
		now := time.Now()
		hours := []int{9, 12, 15, 18, 21} // Business and non-business hours
		for _, hour := range hours {
			snapshot := capture.StatsSnapshot{
				TotalPackets: uint64(100 * (hour - 8)), // More traffic during business hours
				TotalBytes:   uint64(1000 * (hour - 8)),
				PacketsByProtocol: map[string]uint64{
					"TCP": uint64(80 * (hour - 8)),
					"UDP": uint64(20 * (hour - 8)),
				},
				BytesByProtocol: map[string]uint64{
					"TCP": uint64(800 * (hour - 8)),
					"UDP": uint64(200 * (hour - 8)),
				},
				LastUpdated: time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location()),
			}
			manager.AddMetrics(snapshot)
		}

		// Wait for processing
		time.Sleep(2 * time.Second)

		// Verify time-based patterns
		tcpStats, ok := manager.GetProtocolStats("TCP")
		require.True(t, ok)

		// Business hours should show higher traffic
		assert.Greater(t, tcpStats.MediumTermVolume.GetValue(), tcpStats.LongTermVolume.GetValue())
	})
}
