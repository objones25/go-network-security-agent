package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/alert"
	"github.com/objones25/go-network-security-agent/pkg/dashboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDashboardServerIntegration(t *testing.T) {
	// Create a real alert manager for integration testing
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Start the server
	server := dashboard.NewDashboardServer(":8081", manager)
	go func() {
		err := server.Start()
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Server failed to start: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Test health endpoint
	resp, err := http.Get("http://localhost:8081/api/health")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Test metrics endpoint
	resp, err = http.Get("http://localhost:8081/metrics")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestDashboardMetricsIntegration(t *testing.T) {
	// Create a real alert manager for integration testing
	manager, err := alert.NewManager()
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	server := dashboard.NewDashboardServer(":8082", manager)
	go server.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Stop(ctx)
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Make multiple requests to generate metrics
	for i := 0; i < 5; i++ {
		resp, err := http.Get("http://localhost:8082/api/health")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Check metrics
	resp, err := http.Get("http://localhost:8082/metrics")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the entire response
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	metricsData := string(body)

	// Check for our custom metrics
	assert.Contains(t, metricsData, "http_requests_total")
	assert.Contains(t, metricsData, `http_requests_total{endpoint="/api/health",method="GET"}`)
	resp.Body.Close()
}
