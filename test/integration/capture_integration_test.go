package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
)

// setupHTTPServer creates and starts an HTTP server for testing
func setupHTTPServer(t *testing.T) (*http.Server, error) {
	t.Helper() // Mark this as a helper function for better test output

	t.Log("Setting up HTTP test server...")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	serverReady := make(chan error)
	go func() {
		t.Log("Starting HTTP server on :8080")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
			serverReady <- err
		}
		close(serverReady)
	}()

	// Wait for server to start or error
	t.Log("Waiting for server to be ready...")
	time.Sleep(time.Second)
	select {
	case err := <-serverReady:
		if err != nil {
			t.Logf("Server failed to start: %v", err)
			return nil, err
		}
	default:
		t.Log("Server started successfully")
	}

	return server, nil
}

func TestRealNetworkTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start HTTP server
	server, err := setupHTTPServer(t)
	if err != nil {
		t.Fatalf("Failed to start HTTP server: %v", err)
	}
	defer server.Close()

	// Configure packet capture
	config := capture.Config{
		Interface:   "lo0", // Using loopback interface for testing
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second * 5,
	}

	engine, err := capture.NewPCAPEngine(config)
	if err != nil {
		t.Fatalf("Failed to create packet capture engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = engine.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start packet capture: %v", err)
	}
	defer engine.Stop()

	// Wait for capture to start
	time.Sleep(time.Second)

	// Generate HTTP traffic
	client := &http.Client{Timeout: time.Second * 2}
	resp, err := client.Get("http://localhost:8080")
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Collect and verify packets
	packetChan := engine.Packets()
	packets := make([]capture.Packet, 0)
	timeout := time.After(5 * time.Second)

	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				goto AnalyzePackets
			}
			t.Logf("Captured packet: proto=%s src=%s dst=%s srcPort=%d dstPort=%d",
				packet.Protocol,
				packet.Source,
				packet.Destination,
				packet.SrcPort,
				packet.DstPort)
			packets = append(packets, packet)
			if len(packets) >= 10 {
				goto AnalyzePackets
			}
		case <-timeout:
			goto AnalyzePackets
		}
	}

AnalyzePackets:
	t.Logf("Captured %d packets", len(packets))
	assert.NotEmpty(t, packets, "Should have captured some packets")

	// Look for HTTP traffic
	foundHTTP := false
	for _, packet := range packets {
		if packet.Protocol == "TCP" {
			if packet.SrcPort == 8080 || packet.DstPort == 8080 {
				foundHTTP = true
				t.Logf("Found HTTP packet: %s -> %s", packet.Source, packet.Destination)
				break
			}
		}
	}
	assert.True(t, foundHTTP, "Should have captured HTTP traffic")
}

func TestCaptureStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	// Start HTTP server
	server, err := setupHTTPServer(t)
	if err != nil {
		t.Fatalf("Failed to start HTTP server: %v", err)
	}
	defer server.Close()

	config := capture.Config{
		Interface:   "lo0",
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second * 5,
	}

	engine, err := capture.NewPCAPEngine(config)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = engine.Start(ctx)
	assert.NoError(t, err)
	defer engine.Stop()

	// Generate continuous traffic
	go func() {
		client := &http.Client{Timeout: time.Second}
		for i := 0; i < 20 && ctx.Err() == nil; i++ {
			resp, err := client.Get("http://localhost:8080")
			if err == nil {
				resp.Body.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Monitor resource usage while capturing
	packetChan := engine.Packets()
	packetCount := 0
	start := time.Now()

	for {
		select {
		case _, ok := <-packetChan:
			if !ok {
				return
			}
			packetCount++
		case <-ctx.Done():
			duration := time.Since(start)
			t.Logf("Processed %d packets in %v (%.2f packets/sec)",
				packetCount,
				duration,
				float64(packetCount)/duration.Seconds())
			return
		}
	}
}
