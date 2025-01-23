package integration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/anomaly"
	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseConnectionKey parses a connection key in the format "source:port->destination:port"
func parseConnectionKey(key string) (srcIP, srcPort, dstIP, dstPort string, err error) {
	parts := strings.Split(key, "->")
	if len(parts) != 2 {
		return "", "", "", "", fmt.Errorf("invalid connection key format")
	}

	src := strings.Split(parts[0], ":")
	dst := strings.Split(parts[1], ":")
	if len(src) != 2 || len(dst) != 2 {
		return "", "", "", "", fmt.Errorf("invalid IP:port format")
	}

	return src[0], src[1], dst[0], dst[1], nil
}

// Define test rule condition
type testCondition struct {
	category anomaly.RuleCategory
}

func (c *testCondition) Evaluate(ctx *anomaly.DetectionContext) bool {
	switch c.category {
	case anomaly.CategoryTrafficVolume:
		return ctx.CurrentSnapshot.TotalPackets > 50000
	case anomaly.CategoryPortScan:
		uniquePorts := make(map[string]map[uint16]bool)
		attemptsBySource := make(map[string]int)

		for connKey, attempts := range ctx.CurrentSnapshot.ActiveConnections {
			srcIP, _, _, dstPortStr, err := parseConnectionKey(connKey)
			if err != nil {
				continue
			}

			dstPort, err := strconv.ParseUint(dstPortStr, 10, 16)
			if err != nil {
				continue
			}

			if _, exists := uniquePorts[srcIP]; !exists {
				uniquePorts[srcIP] = make(map[uint16]bool)
			}
			uniquePorts[srcIP][uint16(dstPort)] = true
			attemptsBySource[srcIP] += int(attempts)
		}

		// Check for port scan patterns with lower thresholds for testing
		for src, ports := range uniquePorts {
			if len(ports) > 25 && attemptsBySource[src] > 25 { // Lower thresholds
				return true
			}
		}
		return false
	case anomaly.CategoryProtocolAnomaly:
		if tcpPackets, ok := ctx.CurrentSnapshot.PacketsByProtocol["TCP"]; ok {
			return tcpPackets > 50000
		}
		return false
	default:
		return false
	}
}

func (c *testCondition) Description() string {
	return fmt.Sprintf("Test condition for %s", c.category)
}

func TestAnomalyDetectionIntegration(t *testing.T) {
	// Initialize baseline manager with test configuration
	baselineCfg := baseline.DefaultConfig()
	baselineMgr, err := baseline.NewManager(baselineCfg)
	require.NoError(t, err)

	// Initialize detector with test rules
	detector, err := anomaly.NewDetector(baselineMgr)
	require.NoError(t, err)

	// Configure detector
	err = detector.Configure(anomaly.DetectorConfig{
		MinConfidenceScore: 0.8,
		DetectionInterval:  time.Second * 30,
		MaxAlertHistory:    1000,
		AdaptiveThresholds: true,
		CorrelationWindow:  time.Minute * 5,
		MinCorrelation:     0.7,
	})
	require.NoError(t, err)

	// Add test rules
	trafficRule := anomaly.Rule{
		ID:          "tv1",
		Name:        "Traffic Volume Anomaly",
		Description: "Detects abnormal traffic volume",
		Category:    anomaly.CategoryTrafficVolume,
		Severity:    anomaly.SeverityWarning,
		Threshold:   3.0,
		Enabled:     true,
		Condition:   &testCondition{category: anomaly.CategoryTrafficVolume},
	}
	err = detector.AddRule(trafficRule)
	require.NoError(t, err)

	protocolRule := anomaly.Rule{
		ID:          "pa1",
		Name:        "Protocol Anomaly",
		Description: "Detects protocol-specific anomalies",
		Category:    anomaly.CategoryProtocolAnomaly,
		Severity:    anomaly.SeverityWarning,
		Threshold:   3.0,
		Enabled:     true,
		Condition:   &testCondition{category: anomaly.CategoryProtocolAnomaly},
	}
	err = detector.AddRule(protocolRule)
	require.NoError(t, err)

	portScanRule := anomaly.Rule{
		ID:          "ps1",
		Name:        "Port Scan Detection",
		Description: "Detects potential port scanning activity",
		Category:    anomaly.CategoryPortScan,
		Severity:    anomaly.SeverityWarning,
		Threshold:   25.0, // Lower threshold for testing
		Enabled:     true,
		Condition:   &testCondition{category: anomaly.CategoryPortScan},
	}
	err = detector.AddRule(portScanRule)
	require.NoError(t, err)

	// Start the detector
	err = detector.Start(context.Background())
	require.NoError(t, err)
	defer detector.Stop()

	t.Run("Normal Traffic Pattern", func(t *testing.T) {
		// Create normal traffic snapshot
		snapshot := capture.StatsSnapshot{
			TotalPackets: 1000,
			TotalBytes:   150000,
			PacketsByProtocol: map[string]uint64{
				"TCP": 800,
				"UDP": 200,
			},
			BytesByProtocol: map[string]uint64{
				"TCP": 120000,
				"UDP": 30000,
			},
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80":   1,
				"192.168.1.100:12346->10.0.0.1:443":  1,
				"192.168.1.101:22222->10.0.0.2:8080": 1,
			},
		}

		// Establish baseline
		for i := 0; i < 15; i++ {
			baselineMgr.AddMetrics(snapshot)
			time.Sleep(time.Millisecond * 100)
		}

		// Verify no alerts for normal traffic
		alerts := detector.Detect(snapshot)
		assert.Empty(t, alerts, "No alerts should be generated for normal traffic")
	})

	t.Run("Port Scan Detection", func(t *testing.T) {
		// Create snapshot with port scan pattern
		snapshot := capture.StatsSnapshot{
			TotalPackets: 2000,
			TotalBytes:   50000,
			PacketsByProtocol: map[string]uint64{
				"TCP": 1800,
				"UDP": 200,
			},
			ActiveConnections: make(map[string]uint64),
		}

		// Add port scan pattern - 30 different ports with 2 attempts each
		srcIP := "192.168.1.100"
		for port := 1; port <= 30; port++ {
			connKey := fmt.Sprintf("%s:12345->10.0.0.1:%d", srcIP, port)
			snapshot.ActiveConnections[connKey] = 2
		}

		// Run detection
		alerts := detector.Detect(snapshot)

		// Wait a bit for alert processing
		time.Sleep(time.Second)

		// Get alerts from the last minute
		alerts = detector.GetAlerts(time.Now().Add(-time.Minute))

		// Verify port scan was detected
		require.NotEmpty(t, alerts, "Port scan should be detected")
		assert.Equal(t, string(anomaly.CategoryPortScan), alerts[0].MetricName, "Alert should be for port scan")
	})

	t.Run("Traffic Volume Anomaly", func(t *testing.T) {
		// Create snapshot with abnormal traffic volume
		snapshot := capture.StatsSnapshot{
			TotalPackets: 100000, // 100x normal
			TotalBytes:   15000000,
			PacketsByProtocol: map[string]uint64{
				"TCP": 80000,
				"UDP": 20000,
			},
			BytesByProtocol: map[string]uint64{
				"TCP": 12000000,
				"UDP": 3000000,
			},
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80": 1,
			},
		}

		// Process snapshot and verify alerts
		alerts := detector.Detect(snapshot)
		assert.NotEmpty(t, alerts, "Traffic volume anomaly should be detected")
		assert.Equal(t, string(anomaly.CategoryTrafficVolume), alerts[0].MetricName)
	})
}
