package unit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
)

func TestStatsSnapshot(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)
	assert.NotNil(t, engine)

	// Get initial snapshot
	snapshot := engine.GetStats()
	assert.Equal(t, uint64(0), snapshot.TotalPackets)
	assert.Equal(t, uint64(0), snapshot.TotalBytes)
	assert.NotNil(t, snapshot.PacketsByProtocol)
	assert.NotNil(t, snapshot.BytesByProtocol)
	assert.NotNil(t, snapshot.ActiveConnections)

	// Test concurrent access to stats
	var wg sync.WaitGroup
	updateCount := 100
	wg.Add(updateCount)

	// Simulate multiple goroutines updating stats
	for i := 0; i < updateCount; i++ {
		go func() {
			defer wg.Done()
			engine.UpdateStats(capture.Packet{
				Protocol:    "TCP",
				Length:      100,
				Source:      "192.168.1.1:12345",
				Destination: "192.168.1.2:80",
				SrcPort:     12345,
				DstPort:     80,
			})
		}()
	}

	wg.Wait()

	// Verify final stats
	finalSnapshot := engine.GetStats()
	assert.Equal(t, uint64(updateCount), finalSnapshot.TotalPackets)
	assert.Equal(t, uint64(updateCount*100), finalSnapshot.TotalBytes)
	assert.Equal(t, uint64(updateCount), finalSnapshot.PacketsByProtocol["TCP"])
	assert.Equal(t, uint64(updateCount*100), finalSnapshot.BytesByProtocol["TCP"])

	// Test deep copy of maps
	snapshot = engine.GetStats()
	originalProtoCount := snapshot.PacketsByProtocol["TCP"]

	// Modify the snapshot (shouldn't affect internal stats)
	snapshot.PacketsByProtocol["TCP"] = 0
	newSnapshot := engine.GetStats()
	assert.Equal(t, originalProtoCount, newSnapshot.PacketsByProtocol["TCP"])
}

func TestStatsConsistency(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = engine.Start(ctx)
	assert.NoError(t, err)
	defer engine.Stop()

	// Take multiple snapshots while updating stats
	var snapshots []capture.StatsSnapshot
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine to collect snapshots
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			snapshots = append(snapshots, engine.GetStats())
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Goroutine to update stats
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			engine.UpdateStats(capture.Packet{
				Protocol:    "TCP",
				Length:      100,
				Source:      "192.168.1.1:12345",
				Destination: "192.168.1.2:80",
				SrcPort:     12345,
				DstPort:     80,
			})
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Verify snapshots are monotonically increasing
	for i := 1; i < len(snapshots); i++ {
		assert.GreaterOrEqual(t,
			snapshots[i].TotalPackets,
			snapshots[i-1].TotalPackets,
			"Packet count should be monotonically increasing")
		assert.GreaterOrEqual(t,
			snapshots[i].TotalBytes,
			snapshots[i-1].TotalBytes,
			"Byte count should be monotonically increasing")
	}
}

func TestStatsReset(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)

	// Add some stats
	engine.UpdateStats(capture.Packet{
		Protocol:    "TCP",
		Length:      100,
		Source:      "192.168.1.1:12345",
		Destination: "192.168.1.2:80",
		SrcPort:     12345,
		DstPort:     80,
	})

	// Verify stats were added
	snapshot := engine.GetStats()
	assert.Equal(t, uint64(1), snapshot.TotalPackets)

	// Reset stats
	engine.ResetStats()

	// Verify stats were reset
	snapshot = engine.GetStats()
	assert.Equal(t, uint64(0), snapshot.TotalPackets)
	assert.Equal(t, uint64(0), snapshot.TotalBytes)
	assert.Empty(t, snapshot.PacketsByProtocol)
	assert.Empty(t, snapshot.BytesByProtocol)
	assert.Empty(t, snapshot.ActiveConnections)
}

// TestMultipleProtocols tests stats collection for different protocols
func TestMultipleProtocols(t *testing.T) {
	engine, err := capture.NewPCAPEngine(capture.Config{Interface: "lo0"})
	assert.NoError(t, err)

	// Add packets for different protocols
	protocols := []struct {
		proto string
		port  uint16
		app   string
	}{
		{"TCP", 80, "HTTP"},
		{"TCP", 443, "HTTPS"},
		{"UDP", 53, "DNS"},
		{"TCP", 22, "SSH"},
	}

	for _, p := range protocols {
		engine.UpdateStats(capture.Packet{
			Protocol:    p.proto,
			Length:      100,
			Source:      "192.168.1.1",
			Destination: "192.168.1.2",
			SrcPort:     12345,
			DstPort:     p.port,
			Application: p.app,
		})
	}

	stats := engine.GetStats()
	assert.Equal(t, uint64(len(protocols)), stats.TotalPackets)
	assert.Equal(t, uint64(len(protocols)*100), stats.TotalBytes)
	assert.Equal(t, uint64(3), stats.PacketsByProtocol["TCP"])
	assert.Equal(t, uint64(1), stats.PacketsByProtocol["UDP"])
}

// TestConnectionTracking tests the connection tracking functionality
func TestConnectionTracking(t *testing.T) {
	engine, err := capture.NewPCAPEngine(capture.Config{Interface: "lo0"})
	assert.NoError(t, err)

	// Simulate bidirectional traffic
	connections := []struct {
		src     string
		dst     string
		srcPort uint16
		dstPort uint16
	}{
		{"192.168.1.1", "192.168.1.2", 12345, 80},
		{"192.168.1.2", "192.168.1.1", 80, 12345}, // Return traffic
		{"192.168.1.1", "192.168.1.2", 12346, 80}, // New connection
	}

	for _, conn := range connections {
		engine.UpdateStats(capture.Packet{
			Protocol:    "TCP",
			Length:      100,
			Source:      conn.src,
			Destination: conn.dst,
			SrcPort:     conn.srcPort,
			DstPort:     conn.dstPort,
		})
	}

	stats := engine.GetStats()
	assert.Equal(t, uint64(3), stats.TotalPackets)
	assert.Equal(t, uint64(3), uint64(len(stats.ActiveConnections)))

	// Verify specific connections
	connKey1 := "192.168.1.1:12345->192.168.1.2:80"
	connKey2 := "192.168.1.2:80->192.168.1.1:12345"
	assert.Equal(t, uint64(1), stats.ActiveConnections[connKey1])
	assert.Equal(t, uint64(1), stats.ActiveConnections[connKey2])
}

// TestLargeVolume tests handling of large numbers of packets
func TestLargeVolume(t *testing.T) {
	engine, err := capture.NewPCAPEngine(capture.Config{Interface: "lo0"})
	assert.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 10
	packetsPerGoroutine := 1000
	wg.Add(numGoroutines)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer wg.Done()
			for j := 0; j < packetsPerGoroutine; j++ {
				engine.UpdateStats(capture.Packet{
					Protocol:    "TCP",
					Length:      100,
					Source:      fmt.Sprintf("192.168.1.%d", routineID),
					Destination: "192.168.2.1",
					SrcPort:     uint16(12345 + routineID),
					DstPort:     80,
				})
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	stats := engine.GetStats()
	expectedPackets := uint64(numGoroutines * packetsPerGoroutine)
	assert.Equal(t, expectedPackets, stats.TotalPackets)
	assert.Equal(t, expectedPackets*100, stats.TotalBytes)

	t.Logf("Processed %d packets in %v (%.2f packets/sec)",
		expectedPackets,
		duration,
		float64(expectedPackets)/duration.Seconds())
}

// TestStatsPeriodicity tests the periodic stats collection
func TestStatsPeriodicity(t *testing.T) {
	config := capture.Config{
		Interface:   "lo0",
		StatsPeriod: 100 * time.Millisecond,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = engine.Start(ctx)
	assert.NoError(t, err)
	defer engine.Stop()

	// Wait for multiple stats collection cycles
	time.Sleep(400 * time.Millisecond)
}

// TestBPFFilter tests the BPF filter functionality
func TestBPFFilter(t *testing.T) {
	engine, err := capture.NewPCAPEngine(capture.Config{Interface: "lo0"})
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = engine.Start(ctx)
	assert.NoError(t, err)
	defer engine.Stop()

	// Test setting valid filter
	err = engine.SetBPFFilter("tcp and port 80")
	assert.NoError(t, err)

	// Test setting invalid filter
	err = engine.SetBPFFilter("invalid filter")
	assert.Error(t, err)
}
