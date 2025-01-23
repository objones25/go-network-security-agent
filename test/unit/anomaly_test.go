package unit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/anomaly"
	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
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

func TestTrafficVolumeRule(t *testing.T) {
	rule := anomaly.NewTrafficVolumeRule("test_volume", 3.0)

	t.Run("Normal Traffic", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			TotalPackets: 1000,
			TotalBytes:   150000,
		}
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"packet_variance": baseline.NewVarianceTracker(),
			},
		}

		// Add some normal samples
		variance := ctx.Metadata["packet_variance"].(*baseline.VarianceTracker)
		for i := 0; i < 10; i++ {
			variance.Add(1000 + float64(i*100))
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect anomaly in normal traffic")
	})

	t.Run("Anomalous Traffic", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			TotalPackets: 10000, // 10x normal
			TotalBytes:   1500000,
		}
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"packet_variance": baseline.NewVarianceTracker(),
			},
		}

		// Add normal samples first
		variance := ctx.Metadata["packet_variance"].(*baseline.VarianceTracker)
		for i := 0; i < 10; i++ {
			variance.Add(1000 + float64(i*100))
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect anomaly in high traffic")
	})
}

func TestPortScanRule(t *testing.T) {
	rule := anomaly.NewPortScanRule("test_portscan", 10, 50, time.Minute)

	t.Run("Normal Connections", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80":  1,
				"192.168.1.100:12346->10.0.0.1:443": 1,
			},
		}
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect port scan in normal connections")
	})

	t.Run("Port Scan Pattern", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			ActiveConnections: map[string]uint64{},
		}
		// Add connections to multiple ports from same source with multiple attempts
		for port := 1; port <= 15; port++ {
			connKey := fmt.Sprintf("192.168.1.100:12345->10.0.0.1:%d", port)
			snapshot.ActiveConnections[connKey] = 5 // 5 attempts per port = 75 total attempts
		}

		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect port scan pattern")
	})
}

func TestMalwareActivityRule(t *testing.T) {
	rule := anomaly.NewMalwareActivityRule("test_malware", time.Minute*5, 0.2)

	t.Run("Normal Activity", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			TotalPackets: 1000,
			TotalBytes:   150000,
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80":  1,
				"192.168.1.100:12346->10.0.0.1:443": 1,
			},
		}
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
			},
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect anomaly in normal activity")
	})

	t.Run("Beaconing Pattern", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			TotalPackets:      1000,
			TotalBytes:        150000,
			ActiveConnections: map[string]uint64{},
		}
		// Add beaconing pattern
		connKey := "192.168.1.100:12345->10.0.0.1:6667" // Using known C2 port
		snapshot.ActiveConnections[connKey] = 15        // Multiple connection attempts

		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"connection_times": map[string][]time.Time{
					connKey: {
						time.Now().Add(-15 * time.Minute),
						time.Now().Add(-10 * time.Minute),
						time.Now().Add(-5 * time.Minute),
						time.Now(),
					},
				},
			},
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect beaconing pattern")
	})

	t.Run("Multiple C2 Ports", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			TotalPackets:      1000,
			TotalBytes:        150000,
			ActiveConnections: map[string]uint64{},
		}
		// Add connections to known C2 ports
		c2Ports := []string{"4444", "6667", "8080", "8443"}
		for _, port := range c2Ports {
			connKey := "192.168.1.100:12345->10.0.0.1:" + port
			snapshot.ActiveConnections[connKey] = 15 // Multiple attempts per port
		}

		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
			},
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect multiple C2 port connections")
	})
}

func TestConnectionAnomalyRule(t *testing.T) {
	rule := anomaly.NewConnectionAnomalyRule("test_conn", 10, time.Second*30, 3.0)

	t.Run("Normal Connections", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{
					"192.168.1.100:12345->10.0.0.1:80":  1,
					"192.168.1.100:12346->10.0.0.1:443": 1,
				},
			},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"TCP_stats": &baseline.ProtocolStats{
					ConnectionCount:    baseline.NewEWMA(0.1),
					ConnectionDuration: baseline.NewEWMA(0.1),
					BurstVariance:      baseline.NewVarianceTracker(),
				},
			},
		}

		// Initialize baseline data
		stats := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats)
		for i := 0; i < 10; i++ {
			stats.ConnectionCount.Update(2.0) // Normal connection count
			stats.BurstVariance.Add(2.0)      // Normal burst rate
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect anomaly in normal connections")
	})

	t.Run("Connection Burst", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: make(map[string]uint64),
			},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"TCP_stats": &baseline.ProtocolStats{
					ConnectionCount:    baseline.NewEWMA(0.1),
					ConnectionDuration: baseline.NewEWMA(0.1),
					BurstVariance:      baseline.NewVarianceTracker(),
				},
			},
		}

		// Add connection burst from single source
		srcIP := "192.168.1.10"
		for i := 0; i < 20; i++ {
			connKey := fmt.Sprintf("%s:12345->10.0.0.1:%d", srcIP, 1000+i)
			ctx.CurrentSnapshot.ActiveConnections[connKey] = 1
		}

		// Add burst variance
		burstTracker := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats).BurstVariance
		for i := 0; i < 10; i++ {
			burstTracker.Add(5.0) // Normal burst rate
		}
		burstTracker.Add(20.0) // Sudden burst

		assert.True(t, rule.Evaluate(ctx), "Should detect connection burst anomaly")
	})
}

func TestDataExfiltrationRule(t *testing.T) {
	rule := anomaly.NewDataExfiltrationRule("test_exfil", 1000000, time.Minute*5, 10)

	t.Run("Normal Data Transfer", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{
					"192.168.1.100:12345->10.0.0.1:80":  1,
					"192.168.1.100:12346->10.0.0.1:443": 1,
				},
				BytesByProtocol: map[string]uint64{
					"TCP": 100000,
				},
			},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"TCP_stats": &baseline.ProtocolStats{
					ByteVariance: baseline.NewVarianceTracker(),
				},
			},
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect exfiltration in normal transfer")
	})

	t.Run("Data Exfiltration Pattern", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: make(map[string]uint64),
				BytesByProtocol: map[string]uint64{
					"TCP": 2000000, // Abnormally high
				},
			},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"TCP_stats": &baseline.ProtocolStats{
					ByteVariance: baseline.NewVarianceTracker(),
				},
			},
		}

		// Add multiple external destinations
		srcIP := "192.168.1.10"
		for i := 0; i < 15; i++ {
			connKey := fmt.Sprintf("%s:12345->203.0.113.%d:443", srcIP, i)
			ctx.CurrentSnapshot.ActiveConnections[connKey] = 1
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect data exfiltration pattern")
	})
}

func TestBruteForceRule(t *testing.T) {
	rule := anomaly.NewBruteForceRule("test_brute", 10, time.Minute)

	t.Run("Normal Authentication", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{
					"192.168.1.100:12345->10.0.0.1:22": 2,
					"192.168.1.100:12346->10.0.0.1:80": 1,
				},
			},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"TCP_stats": &baseline.ProtocolStats{
					PacketVariance: baseline.NewVarianceTracker(),
				},
			},
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect brute force in normal auth")
	})

	t.Run("Brute Force Pattern", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{
					"192.168.1.10:12345->10.0.0.1:22": 20, // Many SSH attempts
				},
			},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"TCP_stats": &baseline.ProtocolStats{
					PacketVariance: baseline.NewVarianceTracker(),
				},
			},
		}

		// Add variance data showing burst
		variance := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats).PacketVariance
		for i := 0; i < 10; i++ {
			variance.Add(10.0)
		}
		variance.Add(100.0) // Sudden burst

		assert.True(t, rule.Evaluate(ctx), "Should detect brute force pattern")
	})
}

func TestParseConnectionKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		wantSrcIP   string
		wantSrcPort string
		wantDstIP   string
		wantDstPort string
		wantErr     bool
	}{
		{
			name:        "Valid Connection Key",
			key:         "192.168.1.100:12345->10.0.0.1:80",
			wantSrcIP:   "192.168.1.100",
			wantSrcPort: "12345",
			wantDstIP:   "10.0.0.1",
			wantDstPort: "80",
			wantErr:     false,
		},
		{
			name:    "Invalid Separator",
			key:     "192.168.1.100:12345=>10.0.0.1:80",
			wantErr: true,
		},
		{
			name:    "Missing Port",
			key:     "192.168.1.100->10.0.0.1:80",
			wantErr: true,
		},
		{
			name:    "Empty String",
			key:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP, srcPort, dstIP, dstPort, err := parseConnectionKey(tt.key)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantSrcIP, srcIP)
			assert.Equal(t, tt.wantSrcPort, srcPort)
			assert.Equal(t, tt.wantDstIP, dstIP)
			assert.Equal(t, tt.wantDstPort, dstPort)
		})
	}
}

func TestProtocolAnomalyRule(t *testing.T) {
	rule := anomaly.NewProtocolAnomalyRule("test_protocol", "TCP", 3.0, 0.8)

	t.Run("Normal Protocol Distribution", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			PacketsByProtocol: map[string]uint64{
				"TCP":  800,
				"UDP":  150,
				"ICMP": 50,
			},
			BytesByProtocol: map[string]uint64{
				"TCP":  80000,
				"UDP":  15000,
				"ICMP": 5000,
			},
		}
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.9,
				},
				"TCP_stats": &baseline.ProtocolStats{
					PacketVariance: baseline.NewVarianceTracker(),
					ByteVariance:   baseline.NewVarianceTracker(),
				},
			},
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect anomaly in normal protocol distribution")
	})

	t.Run("Abnormal Protocol Distribution", func(t *testing.T) {
		snapshot := capture.StatsSnapshot{
			PacketsByProtocol: map[string]uint64{
				"TCP":  8000, // 10x normal
				"UDP":  150,
				"ICMP": 50,
			},
			BytesByProtocol: map[string]uint64{
				"TCP":  800000,
				"UDP":  15000,
				"ICMP": 5000,
			},
		}

		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: snapshot,
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.9,
				},
				"TCP_stats": &baseline.ProtocolStats{
					PacketVariance: baseline.NewVarianceTracker(),
					ByteVariance:   baseline.NewVarianceTracker(),
				},
			},
		}

		// Initialize baseline data
		stats := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats)
		for i := 0; i < 10; i++ {
			stats.PacketVariance.Add(800.0) // Normal packet count
			stats.ByteVariance.Add(80000.0) // Normal byte count
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect anomaly in protocol distribution")
	})
}

func TestRuleCorrelation(t *testing.T) {
	portScanRule := anomaly.NewPortScanRule("portscan", 10, 50, time.Minute)
	malwareRule := anomaly.NewMalwareActivityRule("malware", time.Minute*5, 0.2)

	snapshot := capture.StatsSnapshot{
		TotalPackets:      10000,
		TotalBytes:        1500000,
		ActiveConnections: map[string]uint64{},
		PacketsByProtocol: map[string]uint64{
			"TCP": 9000,
			"UDP": 1000,
		},
	}

	// Add port scan pattern with multiple attempts
	for port := 1; port <= 15; port++ {
		connKey := fmt.Sprintf("192.168.1.100:12345->10.0.0.1:%d", port)
		snapshot.ActiveConnections[connKey] = 5 // 5 attempts per port = 75 total attempts
	}

	// Add beaconing pattern to C2 port
	c2ConnKey := "192.168.1.100:12345->10.0.0.1:6667"
	snapshot.ActiveConnections[c2ConnKey] = 15

	ctx := &anomaly.DetectionContext{
		CurrentSnapshot: snapshot,
		Metadata: map[string]interface{}{
			"baseline_health": baseline.BaselineHealth{
				Confidence: 0.8,
			},
			"packet_variance": baseline.NewVarianceTracker(),
			"connection_times": map[string][]time.Time{
				c2ConnKey: {
					time.Now().Add(-15 * time.Minute),
					time.Now().Add(-10 * time.Minute),
					time.Now().Add(-5 * time.Minute),
					time.Now(),
				},
			},
		},
	}

	// Initialize baseline data
	variance := ctx.Metadata["packet_variance"].(*baseline.VarianceTracker)
	for i := 0; i < 10; i++ {
		variance.Add(1000.0) // Normal packet count
	}

	// Test each rule
	assert.True(t, portScanRule.Evaluate(ctx), "Should detect port scan")
	assert.True(t, malwareRule.Evaluate(ctx), "Should detect malware activity")
}

func TestDNSTunnelingRule(t *testing.T) {
	rule := anomaly.NewDNSTunnelingRule("test_dns", 50.0, 10, 4.5, time.Minute*5)

	t.Run("Normal DNS Traffic", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"dns_queries": map[string][]string{
					"example.com": {
						"www",
						"mail",
						"api",
					},
					"google.com": {
						"www",
						"drive",
						"docs",
					},
				},
			},
		}

		assert.False(t, rule.Evaluate(ctx), "Should not detect tunneling in normal DNS traffic")
	})

	t.Run("DNS Tunneling Pattern", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"dns_queries": map[string][]string{
					"malicious.com": {
						// Long base64-encoded subdomains
						"aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnktbG9uZy1zdHJpbmc",
						"dGhpcy1pcy1hbm90aGVyLXZlcnktbG9uZy1zdHJpbmctZm9yLXRlc3Rpbmc",
						"eWV0LWFub3RoZXItbG9uZy1zdHJpbmctZm9yLXRlc3Rpbmctd2l0aC1iYXNlNjQ",
					},
				},
			},
		}

		assert.True(t, rule.Evaluate(ctx), "Should detect DNS tunneling pattern")
	})

	t.Run("Excessive Subdomains", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{},
			Metadata: map[string]interface{}{
				"baseline_health": baseline.BaselineHealth{
					Confidence: 0.8,
				},
				"dns_queries": map[string][]string{
					"suspicious.com": {},
				},
			},
		}

		// Add many unique subdomains
		subdomains := ctx.Metadata["dns_queries"].(map[string][]string)["suspicious.com"]
		for i := 0; i < 20; i++ {
			subdomains = append(subdomains, fmt.Sprintf("sub%d", i))
		}
		ctx.Metadata["dns_queries"].(map[string][]string)["suspicious.com"] = subdomains

		assert.True(t, rule.Evaluate(ctx), "Should detect excessive unique subdomains")
	})
}

func TestTLSAnomalyRule(t *testing.T) {
	rule := anomaly.NewTLSAnomalyRule(
		"tls_test",
		24*time.Hour,     // minCertAge
		365*time.Hour*24, // maxCertAge
		0.1,              // weakCipherThreshold
		0.05,             // selfSignedThreshold
	)

	// Test normal TLS traffic
	ctx := &anomaly.DetectionContext{
		CurrentSnapshot: capture.StatsSnapshot{
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:443": 100,
				"192.168.1.100:12346->10.0.0.2:443": 50,
				"192.168.1.100:12347->10.0.0.3:80":  30, // Non-TLS traffic
			},
		},
		Metadata: map[string]interface{}{
			"tls_data": map[string]interface{}{
				"192.168.1.100:12345->10.0.0.1:443": map[string]interface{}{
					"cipher_suite":    uint16(0x1301), // TLS_AES_128_GCM_SHA256 (strong)
					"ja3_fingerprint": "771,49195-49199-49196-49200-159-52393-52392-52394,0-23-65281-10-11-35-16-5-13-28-21,29-23-24,0",
					"certificate": map[string]interface{}{
						"self_signed":     false,
						"ct_logs_present": true,
					},
				},
				"192.168.1.100:12346->10.0.0.2:443": map[string]interface{}{
					"cipher_suite":    uint16(0x1302), // TLS_AES_256_GCM_SHA384 (strong)
					"ja3_fingerprint": "771,49196-49195-49200-49199-159-49188-49187-49192-49191-49162-49161-52393-49172-49171,0-23-65281-10-11-35-16-5-13-28-21,29-23-24,0",
					"certificate": map[string]interface{}{
						"self_signed":     false,
						"ct_logs_present": true,
					},
				},
			},
		},
	}

	result, err := rule.Evaluate(ctx)
	assert.NoError(t, err)
	assert.False(t, result, "Should not trigger on normal TLS traffic")

	// Test high weak cipher usage
	ctx = &anomaly.DetectionContext{
		CurrentSnapshot: capture.StatsSnapshot{
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:443": 1000,
			},
		},
		Metadata: map[string]interface{}{
			"tls_data": map[string]interface{}{
				"192.168.1.100:12345->10.0.0.1:443": map[string]interface{}{
					"cipher_suite":    uint16(0x0004), // TLS_RSA_WITH_RC4_128_MD5 (weak)
					"ja3_fingerprint": "771,49195-49199-49196-49200-159-52393-52392-52394,0-23-65281-10-11-35-16-5-13-28-21,29-23-24,0",
					"certificate": map[string]interface{}{
						"self_signed":     false,
						"ct_logs_present": true,
					},
				},
			},
		},
	}

	result, err = rule.Evaluate(ctx)
	assert.NoError(t, err)
	assert.True(t, result, "Should detect high weak cipher usage")
}

func TestLateralMovementRule(t *testing.T) {
	rule := anomaly.NewLateralMovementRule(
		"lateral_test",
		5,         // uniqueHostThreshold
		time.Hour, // timeWindow
		3.0,       // scanPatternThreshold
	)

	t.Run("Normal Activity", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{
					"192.168.1.100:12345->10.0.0.1:445": 1,
					"192.168.1.100:12345->10.0.0.2:445": 1,
				},
			},
			Metadata: map[string]interface{}{
				"auth_data": map[string]interface{}{
					"credentials": map[string]map[string]int{
						"user1": {
							"10.0.0.1": 1,
							"10.0.0.2": 1,
						},
					},
					"failed_attempts": map[string]int{
						"10.0.0.1": 2,
					},
				},
				"process_data": map[string]interface{}{
					"process_list":   []string{"svchost.exe", "explorer.exe"},
					"process_chains": [][]string{{"cmd.exe", "powershell.exe"}},
				},
				"session_data": map[string][]string{
					"10.0.0.1": {"session1"},
				},
			},
		}

		result, err := rule.Evaluate(ctx)
		assert.NoError(t, err)
		assert.False(t, result, "Should not detect lateral movement in normal activity")
	})

	t.Run("Sequential Port Scanning", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{},
			},
			Metadata: map[string]interface{}{
				"auth_data": map[string]interface{}{
					"credentials":     map[string]map[string]int{},
					"failed_attempts": map[string]int{},
				},
				"process_data": map[string]interface{}{
					"process_list":   []string{"svchost.exe"},
					"process_chains": [][]string{},
				},
				"session_data": map[string][]string{},
			},
		}

		// Add sequential port scan pattern (ports 445-455)
		for port := 445; port <= 455; port++ {
			connKey := fmt.Sprintf("192.168.1.100:12345->10.0.0.1:%d", port)
			ctx.CurrentSnapshot.ActiveConnections[connKey] = 1
		}

		result, err := rule.Evaluate(ctx)
		assert.NoError(t, err)
		assert.True(t, result, "Should detect sequential port scanning")
	})

	t.Run("Multiple Host Access", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{},
			},
			Metadata: map[string]interface{}{
				"auth_data": map[string]interface{}{
					"credentials":     map[string]map[string]int{},
					"failed_attempts": map[string]int{},
				},
				"process_data": map[string]interface{}{
					"process_list":   []string{"svchost.exe"},
					"process_chains": [][]string{},
				},
				"session_data": map[string][]string{},
			},
		}

		// Add connections to multiple hosts
		for i := 1; i <= 6; i++ {
			connKey := fmt.Sprintf("192.168.1.100:12345->10.0.0.%d:445", i)
			ctx.CurrentSnapshot.ActiveConnections[connKey] = 1
		}

		result, err := rule.Evaluate(ctx)
		assert.NoError(t, err)
		assert.True(t, result, "Should detect access to too many hosts")
	})

	t.Run("Admin Tool Usage", func(t *testing.T) {
		ctx := &anomaly.DetectionContext{
			CurrentSnapshot: capture.StatsSnapshot{
				ActiveConnections: map[string]uint64{
					"192.168.1.100:12345->10.0.0.1:445": 1,
				},
			},
			Metadata: map[string]interface{}{
				"auth_data": map[string]interface{}{
					"credentials":     map[string]map[string]int{},
					"failed_attempts": map[string]int{},
				},
				"process_data": map[string]interface{}{
					"process_list": []string{
						"svchost.exe",
						"psexec.exe -accepteula \\\\10.0.0.1 cmd.exe",
					},
					"process_chains": [][]string{},
				},
				"session_data": map[string][]string{},
			},
		}

		result, err := rule.Evaluate(ctx)
		assert.NoError(t, err)
		assert.True(t, result, "Should detect use of admin tools")
	})
}
func TestGeographicAnomalyRule(t *testing.T) {
	rule := anomaly.NewGeographicAnomalyRule(
		"geo_test",
		[]string{"US", "CA"}, // allowedCountries
		[]int{7922, 13335},   // allowedASNs
		0.2,                  // unknownIPThreshold
	)

	ctx := &anomaly.DetectionContext{
		CurrentSnapshot: capture.StatsSnapshot{
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80": 100,
			},
		},
		Metadata: map[string]interface{}{
			"ip_geolocation": map[string]interface{}{
				"192.168.1.100": map[string]interface{}{
					"country": "US",
					"asn":     7922,
				},
			},
		},
	}

	// Test normal traffic from allowed location
	result, err := rule.Evaluate(ctx)
	assert.NoError(t, err)
	assert.False(t, result, "Should not trigger on traffic from allowed locations")

	// Test traffic from unknown location
	ctx.Metadata["ip_geolocation"] = map[string]interface{}{
		"192.168.1.100": map[string]interface{}{
			"country": "RU",
			"asn":     12345,
		},
	}
	result, err = rule.Evaluate(ctx)
	assert.NoError(t, err)
	assert.True(t, result, "Should detect traffic from unknown location")

	// Test mixed traffic with high ratio of unknown locations
	ctx.CurrentSnapshot.ActiveConnections = map[string]uint64{
		"192.168.1.100:12345->10.0.0.1:80": 80, // Unknown location
		"192.168.1.101:12345->10.0.0.2:80": 20, // Known location
	}
	ctx.Metadata["ip_geolocation"] = map[string]interface{}{
		"192.168.1.100": map[string]interface{}{
			"country": "RU",
			"asn":     12345,
		},
		"192.168.1.101": map[string]interface{}{
			"country": "US",
			"asn":     7922,
		},
	}
	result, err = rule.Evaluate(ctx)
	assert.NoError(t, err)
	assert.True(t, result, "Should detect high ratio of traffic from unknown locations")
}
