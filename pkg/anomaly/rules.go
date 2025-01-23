package anomaly

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/baseline"
)

// BaseRule provides common functionality for all rules
type BaseRule struct {
	id          string
	name        string
	description string
	category    RuleCategory
	severity    AlertSeverity
	enabled     bool
	metadata    map[string]interface{}
}

// TrafficVolumeRule detects anomalies in overall traffic volume
type TrafficVolumeRule struct {
	BaseRule
	zScoreThreshold float64
	minPacketRate   float64
}

func NewTrafficVolumeRule(id string, zScoreThreshold float64) *TrafficVolumeRule {
	return &TrafficVolumeRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Traffic Volume Anomaly",
			description: "Detects abnormal changes in overall traffic volume",
			category:    CategoryTrafficVolume,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		zScoreThreshold: zScoreThreshold,
		minPacketRate:   100, // Minimum packets/sec to consider
	}
}

func (r *TrafficVolumeRule) Evaluate(ctx *DetectionContext) bool {
	// Get baseline health from metadata
	health, ok := ctx.Metadata["baseline_health"].(baseline.BaselineHealth)
	if !ok {
		return false
	}

	// Skip if baseline confidence is too low
	if health.Confidence < 0.5 {
		return false
	}

	currentRate := float64(ctx.CurrentSnapshot.TotalPackets)
	if currentRate < r.minPacketRate {
		return false
	}

	// Check for significant deviation using z-score
	if variance, ok := ctx.Metadata["packet_variance"].(*baseline.VarianceTracker); ok {
		zscore := math.Abs(variance.GetZScore(currentRate))
		return zscore > r.zScoreThreshold
	}

	return false
}

// ProtocolAnomalyRule detects unusual protocol behavior
type ProtocolAnomalyRule struct {
	BaseRule
	protocol        string
	zScoreThreshold float64
	iqrThreshold    float64
}

func NewProtocolAnomalyRule(id string, protocol string, zScoreThreshold, iqrThreshold float64) *ProtocolAnomalyRule {
	return &ProtocolAnomalyRule{
		BaseRule: BaseRule{
			id:          id,
			name:        fmt.Sprintf("%s Protocol Anomaly", protocol),
			description: fmt.Sprintf("Detects abnormal %s protocol behavior", protocol),
			category:    CategoryProtocolAnomaly,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		protocol:        protocol,
		zScoreThreshold: zScoreThreshold,
		iqrThreshold:    iqrThreshold,
	}
}

func (r *ProtocolAnomalyRule) Evaluate(ctx *DetectionContext) bool {
	// Get protocol stats
	currentCount, ok := ctx.CurrentSnapshot.PacketsByProtocol[r.protocol]
	if !ok {
		return false
	}

	// Get protocol variance tracker from metadata
	protoStats, ok := ctx.Metadata[fmt.Sprintf("%s_stats", r.protocol)].(*baseline.ProtocolStats)
	if !ok {
		return false
	}

	// Check using both z-score and IQR
	zscore := math.Abs(protoStats.PacketVariance.GetZScore(float64(currentCount)))
	isZScoreAnomaly := zscore > r.zScoreThreshold

	isIQRAnomaly := protoStats.PacketVariance.IsQuantileAnomaly(float64(currentCount))

	// Consider it anomalous if either test indicates an anomaly
	return isZScoreAnomaly || isIQRAnomaly
}

// DDoSRule detects potential DDoS attacks using multiple indicators
type DDoSRule struct {
	BaseRule
	packetThreshold     float64
	connectionThreshold float64
	burstThreshold      float64
}

func NewDDoSRule(id string, packetThreshold, connectionThreshold, burstThreshold float64) *DDoSRule {
	return &DDoSRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "DDoS Attack Detection",
			description: "Detects potential DDoS attacks using multiple indicators",
			category:    CategoryDDoS,
			severity:    SeverityCritical,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		packetThreshold:     packetThreshold,
		connectionThreshold: connectionThreshold,
		burstThreshold:      burstThreshold,
	}
}

func (r *DDoSRule) Evaluate(ctx *DetectionContext) bool {
	// Get protocol stats for TCP (most common DDoS vector)
	tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats)
	if !ok {
		return false
	}

	// Check multiple indicators
	indicators := 0

	// 1. High packet rate
	if float64(ctx.CurrentSnapshot.TotalPackets) > r.packetThreshold {
		indicators++
	}

	// 2. Connection spike
	if len(ctx.CurrentSnapshot.ActiveConnections) > int(r.connectionThreshold) {
		indicators++
	}

	// 3. Abnormal burst pattern
	if tcpStats.BurstVariance != nil {
		burstScore := tcpStats.BurstVariance.GetLastZScore()
		if math.Abs(burstScore) > r.burstThreshold {
			indicators++
		}
	}

	// 4. Check temporal correlation
	if tcpStats.PacketVariance != nil {
		correlations := tcpStats.PacketVariance.GetCorrelations()
		if correlations["temporal_correlation"] < 0.3 { // Low temporal correlation indicates sudden change
			indicators++
		}
	}

	// Consider it a DDoS if multiple indicators are present
	return indicators >= 2
}

// PortScanRule detects potential port scanning activity
type PortScanRule struct {
	BaseRule
	uniquePortThreshold   int
	timeWindow            time.Duration
	scanAttemptsThreshold int
}

func NewPortScanRule(id string, uniquePortThreshold, scanAttemptsThreshold int, timeWindow time.Duration) *PortScanRule {
	return &PortScanRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Port Scan Detection",
			description: "Detects potential port scanning activity",
			category:    CategoryPortScan,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		uniquePortThreshold:   uniquePortThreshold,
		timeWindow:            timeWindow,
		scanAttemptsThreshold: scanAttemptsThreshold,
	}
}

func (r *PortScanRule) Evaluate(ctx *DetectionContext) bool {
	// Track unique destination ports per source
	portsBySource := make(map[string]map[uint16]bool)
	attemptsBySource := make(map[string]int)

	// Analyze connection attempts
	for connKey, attempts := range ctx.CurrentSnapshot.ActiveConnections {
		// Parse source and destination from connection key
		// Format: "source:port->destination:port"
		srcIP, _, _, dstPort, err := parseConnectionKey(connKey)
		if err != nil {
			continue // Skip malformed connection keys
		}

		// Track unique ports per source
		if _, exists := portsBySource[srcIP]; !exists {
			portsBySource[srcIP] = make(map[uint16]bool)
		}
		portsBySource[srcIP][dstPort] = true
		attemptsBySource[srcIP] += int(attempts)
	}

	// Check for port scan patterns
	for src, ports := range portsBySource {
		if len(ports) > r.uniquePortThreshold && attemptsBySource[src] > r.scanAttemptsThreshold {
			return true
		}
	}

	return false
}

// parseConnectionKey parses a connection key in the format "source:port->destination:port"
func parseConnectionKey(key string) (srcIP string, srcPort uint16, dstIP string, dstPort uint16, err error) {
	parts := strings.Split(key, "->")
	if len(parts) != 2 {
		return "", 0, "", 0, fmt.Errorf("invalid connection key format: missing separator")
	}

	// Parse source
	srcParts := strings.Split(parts[0], ":")
	if len(srcParts) != 2 {
		return "", 0, "", 0, fmt.Errorf("invalid source format")
	}
	srcIP = srcParts[0]
	port, err := strconv.ParseUint(srcParts[1], 10, 16)
	if err != nil {
		return "", 0, "", 0, fmt.Errorf("invalid source port: %v", err)
	}
	srcPort = uint16(port)

	// Parse destination
	dstParts := strings.Split(parts[1], ":")
	if len(dstParts) != 2 {
		return "", 0, "", 0, fmt.Errorf("invalid destination format")
	}
	dstIP = dstParts[0]
	port, err = strconv.ParseUint(dstParts[1], 10, 16)
	if err != nil {
		return "", 0, "", 0, fmt.Errorf("invalid destination port: %v", err)
	}
	dstPort = uint16(port)

	return srcIP, srcPort, dstIP, dstPort, nil
}

// Description returns a human-readable description of the rule
func (r *BaseRule) Description() string {
	return r.description
}

// DataExfiltrationRule detects potential data exfiltration
type DataExfiltrationRule struct {
	BaseRule
	bytesThreshold    float64       // Unusual outbound data volume
	durationThreshold time.Duration // Time window for analysis
	destinationLimit  int           // Max unique destinations
}

func NewDataExfiltrationRule(id string, bytesThreshold float64, durationThreshold time.Duration, destinationLimit int) *DataExfiltrationRule {
	return &DataExfiltrationRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Data Exfiltration Detection",
			description: "Detects potential data exfiltration based on volume and destination patterns",
			category:    CategoryDataExfil,
			severity:    SeverityCritical,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		bytesThreshold:    bytesThreshold,
		durationThreshold: durationThreshold,
		destinationLimit:  destinationLimit,
	}
}

func (r *DataExfiltrationRule) Evaluate(ctx *DetectionContext) bool {
	// Get baseline health from metadata
	health, ok := ctx.Metadata["baseline_health"].(baseline.BaselineHealth)
	if !ok || health.Confidence < 0.5 {
		return false
	}

	// Track outbound data volume per destination
	destVolumes := make(map[string]uint64)
	uniqueDests := make(map[string]bool)

	for connKey := range ctx.CurrentSnapshot.ActiveConnections {
		_, _, dstIP, _, err := parseConnectionKey(connKey)
		if err != nil {
			continue
		}

		// Skip internal destinations (TODO: Add proper internal network detection)
		if strings.HasPrefix(dstIP, "192.168.") || strings.HasPrefix(dstIP, "10.") {
			continue
		}

		uniqueDests[dstIP] = true
		if bytes, ok := ctx.CurrentSnapshot.BytesByProtocol["TCP"]; ok {
			destVolumes[dstIP] += bytes
		}
	}

	// Check for anomalous conditions
	if len(uniqueDests) > r.destinationLimit {
		// Too many unique external destinations
		return true
	}

	// Check volume against baseline
	if tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats); ok {
		for _, volume := range destVolumes {
			if tcpStats.ByteVariance != nil {
				zscore := math.Abs(tcpStats.ByteVariance.GetZScore(float64(volume)))
				if zscore > 3.0 { // Using 3 sigma as threshold
					return true
				}
			}
		}
	}

	return false
}

// BruteForceRule detects authentication brute force attempts
type BruteForceRule struct {
	BaseRule
	failureThreshold int
	timeWindow       time.Duration
	targetPorts      []uint16 // Common auth ports (22, 23, 3389, etc.)
}

func NewBruteForceRule(id string, failureThreshold int, timeWindow time.Duration) *BruteForceRule {
	return &BruteForceRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Brute Force Detection",
			description: "Detects potential authentication brute force attempts",
			category:    CategoryBruteForce,
			severity:    SeverityCritical,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		failureThreshold: failureThreshold,
		timeWindow:       timeWindow,
		targetPorts:      []uint16{22, 23, 3389, 5900, 445, 1433, 3306}, // SSH, Telnet, RDP, VNC, SMB, MSSQL, MySQL
	}
}

func (r *BruteForceRule) Evaluate(ctx *DetectionContext) bool {
	// Track connection attempts per source to authentication ports
	attemptsBySource := make(map[string]int)

	for connKey, attempts := range ctx.CurrentSnapshot.ActiveConnections {
		srcIP, _, _, dstPort, err := parseConnectionKey(connKey)
		if err != nil {
			continue
		}

		// Check if destination port is a common authentication port
		isAuthPort := false
		for _, port := range r.targetPorts {
			if dstPort == port {
				isAuthPort = true
				break
			}
		}

		if isAuthPort {
			attemptsBySource[srcIP] += int(attempts)
		}
	}

	// Check for brute force patterns
	for _, attempts := range attemptsBySource {
		if attempts > r.failureThreshold {
			// Get temporal correlation if available
			if tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats); ok {
				if tcpStats.PacketVariance != nil {
					correlations := tcpStats.PacketVariance.GetCorrelations()
					// Low temporal correlation indicates burst of attempts
					if correlations["temporal_correlation"] < 0.3 {
						return true
					}
				}
			}
			// Even without correlation data, high attempt count is suspicious
			if attempts > r.failureThreshold*2 {
				return true
			}
		}
	}

	return false
}

// ConnectionAnomalyRule detects unusual connection patterns
type ConnectionAnomalyRule struct {
	BaseRule
	maxConnPerSource      int
	connDurationThreshold time.Duration
	burstThreshold        float64
	shortTermWindow       time.Duration
}

func NewConnectionAnomalyRule(id string, maxConnPerSource int, connDurationThreshold time.Duration, burstThreshold float64) *ConnectionAnomalyRule {
	return &ConnectionAnomalyRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Connection Pattern Anomaly",
			description: "Detects unusual connection patterns and behaviors",
			category:    CategoryConnectionSpike,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		maxConnPerSource:      maxConnPerSource,
		connDurationThreshold: connDurationThreshold,
		burstThreshold:        burstThreshold,
		shortTermWindow:       time.Minute * 5,
	}
}

func (r *ConnectionAnomalyRule) Evaluate(ctx *DetectionContext) bool {
	// Get baseline health from metadata
	health, ok := ctx.Metadata["baseline_health"].(baseline.BaselineHealth)
	if !ok || health.Confidence < 0.5 {
		return false
	}

	// Track connections per source
	connsBySource := make(map[string]int)
	connDurations := make(map[string][]time.Duration)

	// Analyze current connections
	for connKey := range ctx.CurrentSnapshot.ActiveConnections {
		srcIP, _, _, _, err := parseConnectionKey(connKey)
		if err != nil {
			continue
		}

		connsBySource[srcIP]++

		// Get connection duration if available
		if tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats); ok {
			if duration := tcpStats.ConnectionDuration.GetValue(); duration > 0 {
				connDurations[srcIP] = append(connDurations[srcIP], time.Duration(duration))
			}
		}
	}

	// Check for anomalous patterns
	for srcIP, count := range connsBySource {
		// 1. Check for too many connections from a single source
		if count > r.maxConnPerSource {
			return true
		}

		// 2. Check for unusual connection durations
		if durations, ok := connDurations[srcIP]; ok {
			var shortConns int
			for _, duration := range durations {
				if duration < r.connDurationThreshold {
					shortConns++
				}
			}
			// If most connections are very short-lived, it's suspicious
			if shortConns > len(durations)*2/3 {
				return true
			}
		}

		// 3. Check for connection bursts using variance tracker
		if tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats); ok {
			if tcpStats.BurstVariance != nil {
				// Check if current burst size is anomalous
				burstScore := tcpStats.BurstVariance.GetLastZScore()
				if math.Abs(burstScore) > r.burstThreshold {
					// Verify with temporal correlation
					correlations := tcpStats.BurstVariance.GetCorrelations()
					if correlations["temporal_correlation"] < 0.3 { // Sudden change in pattern
						return true
					}
				}
			}
		}
	}

	// 4. Check for protocol-specific anomalies
	if tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats); ok {
		// Check for unusual connection count variance
		if tcpStats.ConnectionCount != nil {
			currentCount := float64(len(ctx.CurrentSnapshot.ActiveConnections))
			avgCount := tcpStats.ConnectionCount.GetValue()
			if currentCount > avgCount*2 { // More than double the average
				return true
			}
		}
	}

	return false
}

// MalwareActivityRule detects patterns commonly associated with malware
type MalwareActivityRule struct {
	BaseRule
	beaconThreshold     time.Duration // Minimum time between periodic connections
	beaconJitterPercent float64       // Allowed variance in beacon timing
	dnsQueryThreshold   int           // Maximum unique DNS queries per minute
	encryptedThreshold  float64       // Ratio of encrypted to total traffic
	c2PortList          []uint16      // Known C2 ports to monitor
}

func NewMalwareActivityRule(id string, beaconThreshold time.Duration, beaconJitter float64) *MalwareActivityRule {
	return &MalwareActivityRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Malware Activity Detection",
			description: "Detects patterns commonly associated with malware activity",
			category:    CategoryMalware,
			severity:    SeverityCritical,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		beaconThreshold:     beaconThreshold,
		beaconJitterPercent: beaconJitter,
		dnsQueryThreshold:   100,                                   // 100 unique queries per minute
		encryptedThreshold:  0.9,                                   // 90% encrypted traffic
		c2PortList:          []uint16{6667, 4444, 8080, 8443, 443}, // Common C2 ports
	}
}

func (r *MalwareActivityRule) Evaluate(ctx *DetectionContext) bool {
	// Get baseline health from metadata
	health, ok := ctx.Metadata["baseline_health"].(baseline.BaselineHealth)
	if !ok || health.Confidence < 0.5 {
		return false
	}

	// Track connection patterns per source
	connectionTimes := make(map[string][]time.Time)
	dnsQueries := make(map[string]int)
	c2Attempts := make(map[string]int)
	encryptedBytes := uint64(0)
	totalBytes := uint64(0)

	// Analyze connections
	for connKey, attempts := range ctx.CurrentSnapshot.ActiveConnections {
		srcIP, _, _, dstPort, err := parseConnectionKey(connKey)
		if err != nil {
			continue
		}

		// Track connection times for beaconing detection
		if timestamp, ok := ctx.Metadata[fmt.Sprintf("conn_time_%s", connKey)].(time.Time); ok {
			connectionTimes[srcIP] = append(connectionTimes[srcIP], timestamp)
		}

		// Track DNS queries
		if dstPort == 53 {
			dnsQueries[srcIP]++
		}

		// Check for C2 ports
		for _, port := range r.c2PortList {
			if dstPort == port {
				c2Attempts[srcIP] += int(attempts)
			}
		}

		// Track encrypted vs total traffic
		if bytes, ok := ctx.CurrentSnapshot.BytesByProtocol["TCP"]; ok {
			totalBytes += bytes
			// Assume TLS/HTTPS traffic on standard ports
			if dstPort == 443 || dstPort == 8443 {
				encryptedBytes += bytes
			}
		}
	}

	// 1. Check for beaconing behavior
	for _, times := range connectionTimes {
		if len(times) < 3 {
			continue
		}

		// Sort connection times
		sort.Slice(times, func(i, j int) bool {
			return times[i].Before(times[j])
		})

		// Calculate intervals between connections
		intervals := make([]time.Duration, len(times)-1)
		for i := 0; i < len(times)-1; i++ {
			intervals[i] = times[i+1].Sub(times[i])
		}

		// Check for consistent intervals (allowing for jitter)
		avgInterval := intervals[0]
		consistentCount := 1
		for _, interval := range intervals[1:] {
			diff := math.Abs(float64(interval-avgInterval)) / float64(avgInterval)
			if diff <= r.beaconJitterPercent {
				consistentCount++
			}
		}

		// If most intervals are consistent and within beacon threshold
		if consistentCount >= len(intervals)*2/3 && avgInterval >= r.beaconThreshold {
			return true
		}
	}

	// 2. Check for excessive DNS queries
	for _, queryCount := range dnsQueries {
		if queryCount > r.dnsQueryThreshold {
			return true
		}
	}

	// 3. Check for C2 communication patterns
	for _, attempts := range c2Attempts {
		if attempts > 10 { // More than 10 attempts to known C2 ports
			return true
		}
	}

	// 4. Check encrypted traffic ratio
	if totalBytes > 0 {
		encryptedRatio := float64(encryptedBytes) / float64(totalBytes)
		if encryptedRatio > r.encryptedThreshold {
			// Verify with temporal correlation if available
			if tcpStats, ok := ctx.Metadata["TCP_stats"].(*baseline.ProtocolStats); ok {
				if tcpStats.ByteVariance != nil {
					correlations := tcpStats.ByteVariance.GetCorrelations()
					// Sudden increase in encrypted traffic
					if correlations["temporal_correlation"] < 0.3 {
						return true
					}
				}
			}
		}
	}

	return false
}

// DNSTunnelingRule detects potential data exfiltration via DNS
type DNSTunnelingRule struct {
	BaseRule
	queryLengthThreshold float64       // Unusual query length threshold
	uniqueSubdomainLimit int           // Maximum unique subdomains per domain
	entropyThreshold     float64       // Shannon entropy threshold for detecting encoded data
	timeWindow           time.Duration // Analysis window
}

func NewDNSTunnelingRule(id string, queryLengthThreshold float64, uniqueSubdomainLimit int, entropyThreshold float64, timeWindow time.Duration) *DNSTunnelingRule {
	return &DNSTunnelingRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "DNS Tunneling Detection",
			description: "Detects potential data exfiltration via DNS tunneling",
			category:    CategoryDataExfil,
			severity:    SeverityCritical,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		queryLengthThreshold: queryLengthThreshold,
		uniqueSubdomainLimit: uniqueSubdomainLimit,
		entropyThreshold:     entropyThreshold,
		timeWindow:           timeWindow,
	}
}

// calculateEntropy calculates Shannon entropy of a string
func (r *DNSTunnelingRule) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freqs := make(map[rune]int)
	for _, c := range s {
		freqs[c]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freqs {
		freq := float64(count) / length
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}

func (r *DNSTunnelingRule) Evaluate(ctx *DetectionContext) bool {
	// Get baseline health from metadata
	health, ok := ctx.Metadata["baseline_health"].(baseline.BaselineHealth)
	if !ok || health.Confidence < 0.5 {
		return false
	}

	// Track unique subdomains per domain and query lengths
	subdomainsByDomain := make(map[string]map[string]bool)
	queryLengths := make([]float64, 0)

	// Get DNS queries from metadata
	queries, ok := ctx.Metadata["dns_queries"].(map[string][]string)
	if !ok {
		return false
	}

	// Analyze each query
	for domain, subdomains := range queries {
		if _, exists := subdomainsByDomain[domain]; !exists {
			subdomainsByDomain[domain] = make(map[string]bool)
		}

		for _, subdomain := range subdomains {
			// Track unique subdomains
			subdomainsByDomain[domain][subdomain] = true

			// Calculate query length and entropy
			queryLength := len(subdomain)
			queryLengths = append(queryLengths, float64(queryLength))

			// Check entropy for potential encoded data
			if r.calculateEntropy(subdomain) > r.entropyThreshold {
				return true
			}
		}

		// Check for excessive unique subdomains
		if len(subdomainsByDomain[domain]) > r.uniqueSubdomainLimit {
			return true
		}
	}

	// Calculate average query length
	if len(queryLengths) > 0 {
		var sum float64
		for _, length := range queryLengths {
			sum += length
		}
		avgLength := sum / float64(len(queryLengths))
		if avgLength > r.queryLengthThreshold {
			return true
		}
	}

	return false
}

// TLSAnomalyRule detects unusual SSL/TLS patterns
type TLSAnomalyRule struct {
	BaseRule
	minCertAge          time.Duration   // Minimum acceptable certificate age
	maxCertAge          time.Duration   // Maximum acceptable certificate age
	weakCipherThreshold float64         // Threshold for weak cipher usage
	selfSignedThreshold float64         // Threshold for self-signed certificates
	knownJA3            map[string]bool // Known good JA3 fingerprints
	weakCiphers         map[uint16]bool // Known weak cipher suites
	certTransparency    bool            // Whether to check CT logs
}

func NewTLSAnomalyRule(id string, minCertAge, maxCertAge time.Duration, weakCipherThreshold, selfSignedThreshold float64) *TLSAnomalyRule {
	// Initialize with known weak ciphers
	weakCiphers := map[uint16]bool{
		0x0000: true, // TLS_NULL_WITH_NULL_NULL
		0x0001: true, // TLS_RSA_WITH_NULL_MD5
		0x0002: true, // TLS_RSA_WITH_NULL_SHA
		0x0004: true, // TLS_RSA_WITH_RC4_128_MD5
		0x0005: true, // TLS_RSA_WITH_RC4_128_SHA
		// Add more weak ciphers...
	}

	// Initialize with known good JA3 fingerprints
	knownJA3 := map[string]bool{
		"771,49195-49199-49196-49200-159-52393-52392-52394,0-23-65281-10-11-35-16-5-13-28-21,29-23-24,0":                                     true, // Chrome
		"771,49196-49195-49200-49199-159-49188-49187-49192-49191-49162-49161-52393-49172-49171,0-23-65281-10-11-35-16-5-13-28-21,29-23-24,0": true, // Firefox
		// Add more known good fingerprints...
	}

	return &TLSAnomalyRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "TLS Anomaly Detection",
			description: "Detects unusual SSL/TLS patterns and behaviors",
			category:    CategoryProtocolAnomaly,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		minCertAge:          minCertAge,
		maxCertAge:          maxCertAge,
		weakCipherThreshold: weakCipherThreshold,
		selfSignedThreshold: selfSignedThreshold,
		knownJA3:            knownJA3,
		weakCiphers:         weakCiphers,
		certTransparency:    true,
	}
}

func (r *TLSAnomalyRule) Evaluate(ctx *DetectionContext) (bool, error) {
	weakCipherCount := 0
	selfSignedCount := 0
	unknownJA3Count := 0
	totalConnections := 0

	// Get TLS metadata from context
	tlsData, ok := ctx.Metadata["tls_data"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	// Analyze each TLS connection
	for connKey, count := range ctx.CurrentSnapshot.ActiveConnections {
		if !strings.Contains(connKey, ":443") {
			continue
		}

		totalConnections += int(count)

		// Get connection details
		connData, ok := tlsData[connKey].(map[string]interface{})
		if !ok {
			continue
		}

		// Check JA3 fingerprint
		if ja3, ok := connData["ja3_fingerprint"].(string); ok {
			if !r.knownJA3[ja3] {
				unknownJA3Count += int(count)
			}
		}

		// Check cipher suite
		if cipherSuite, ok := connData["cipher_suite"].(uint16); ok {
			if r.weakCiphers[cipherSuite] {
				weakCipherCount += int(count)
			}
		}

		// Check certificate
		if certData, ok := connData["certificate"].(map[string]interface{}); ok {
			if selfSigned, ok := certData["self_signed"].(bool); ok && selfSigned {
				selfSignedCount += int(count)
			}

			// Check certificate transparency
			if r.certTransparency {
				if ctPresent, ok := certData["ct_logs_present"].(bool); ok && !ctPresent {
					return true, nil // Alert on certificates not in CT logs
				}
			}
		}
	}

	if totalConnections == 0 {
		return false, nil
	}

	// Calculate ratios
	weakCipherRatio := float64(weakCipherCount) / float64(totalConnections)
	selfSignedRatio := float64(selfSignedCount) / float64(totalConnections)
	unknownJA3Ratio := float64(unknownJA3Count) / float64(totalConnections)

	// Check if any thresholds are exceeded
	return weakCipherRatio > r.weakCipherThreshold ||
		selfSignedRatio > r.selfSignedThreshold ||
		unknownJA3Ratio > 0.1, nil // Alert if more than 10% unknown JA3
}

// LateralMovementRule detects potential lateral movement in the network
type LateralMovementRule struct {
	BaseRule
	uniqueHostThreshold  int           // Minimum number of unique hosts contacted to trigger alert
	timeWindow           time.Duration // Time window to check for lateral movement
	scanPatternThreshold float64       // Threshold for sequential port scanning pattern
	credReuseThreshold   int           // Maximum allowed credential reuse
	adminToolPatterns    []string      // Patterns for admin tool detection
	processChainDepth    int           // Maximum allowed process chain depth
}

func NewLateralMovementRule(id string, uniqueHostThreshold int, timeWindow time.Duration, scanPatternThreshold float64) *LateralMovementRule {
	return &LateralMovementRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Lateral Movement Detection",
			description: "Detects potential lateral movement between hosts",
			category:    CategoryLateralMovement,
			severity:    SeverityCritical,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		uniqueHostThreshold:  uniqueHostThreshold,
		timeWindow:           timeWindow,
		scanPatternThreshold: scanPatternThreshold,
		credReuseThreshold:   5, // Alert on same credentials used 5+ times
		adminToolPatterns: []string{
			"psexec",
			"wmic",
			"winrm",
			"powershell",
			"net use",
			"net session",
			"mimikatz",
			"procdump",
			"netsh",
			"reg",
		},
		processChainDepth: 5, // Alert on process chains deeper than 5
	}
}

func (r *LateralMovementRule) Evaluate(ctx *DetectionContext) (bool, error) {
	// Track connections per source IP
	sourceConnections := make(map[string]map[string]bool)  // source IP -> set of destination IPs
	sourcePortsByHost := make(map[string]map[string][]int) // source IP -> dest IP -> sorted port list

	// Get authentication data from metadata
	authData, ok := ctx.Metadata["auth_data"].(map[string]interface{})
	if ok {
		// Check credential reuse
		if creds, ok := authData["credentials"].(map[string]map[string]int); ok {
			for _, hosts := range creds {
				if len(hosts) >= r.credReuseThreshold {
					return true, nil // Alert on excessive credential reuse
				}
			}
		}

		// Check for failed auth attempts
		if failedAuth, ok := authData["failed_attempts"].(map[string]int); ok {
			for _, count := range failedAuth {
				if count >= r.credReuseThreshold {
					return true, nil // Alert on brute force attempts
				}
			}
		}
	}

	// Get process execution data
	if procData, ok := ctx.Metadata["process_data"].(map[string]interface{}); ok {
		// Check for admin tool usage
		if processes, ok := procData["process_list"].([]string); ok {
			for _, proc := range processes {
				for _, pattern := range r.adminToolPatterns {
					if strings.Contains(strings.ToLower(proc), pattern) {
						return true, nil // Alert on admin tool usage
					}
				}
			}
		}

		// Check process chain depth
		if chains, ok := procData["process_chains"].([][]string); ok {
			for _, chain := range chains {
				if len(chain) > r.processChainDepth {
					return true, nil // Alert on deep process chains
				}
			}
		}
	}

	// Process each active connection
	for connKey, count := range ctx.CurrentSnapshot.ActiveConnections {
		if count == 0 {
			continue
		}

		// Parse connection key
		parts := strings.Split(connKey, "->")
		if len(parts) != 2 {
			continue
		}

		srcParts := strings.Split(parts[0], ":")
		dstParts := strings.Split(parts[1], ":")
		if len(srcParts) != 2 || len(dstParts) != 2 {
			continue
		}

		srcIP := srcParts[0]
		dstIP := dstParts[0]
		dstPort, err := strconv.Atoi(dstParts[1])
		if err != nil {
			continue
		}

		// Track unique destinations per source
		if sourceConnections[srcIP] == nil {
			sourceConnections[srcIP] = make(map[string]bool)
		}
		sourceConnections[srcIP][dstIP] = true

		// Track ports per source-destination pair
		if sourcePortsByHost[srcIP] == nil {
			sourcePortsByHost[srcIP] = make(map[string][]int)
		}
		if sourcePortsByHost[srcIP][dstIP] == nil {
			sourcePortsByHost[srcIP][dstIP] = make([]int, 0)
		}
		sourcePortsByHost[srcIP][dstIP] = append(sourcePortsByHost[srcIP][dstIP], dstPort)

		// Check SMB/RDP sessions
		if dstPort == 445 || dstPort == 3389 {
			if sessions, ok := ctx.Metadata["session_data"].(map[string][]string); ok {
				if hostSessions := sessions[dstIP]; len(hostSessions) > r.credReuseThreshold {
					return true, nil // Alert on excessive sessions to same host
				}
			}
		}
	}

	// Check for lateral movement patterns
	for srcIP, dstHosts := range sourceConnections {
		// Check number of unique hosts contacted
		if len(dstHosts) >= r.uniqueHostThreshold {
			return true, nil
		}

		// Check for sequential port scanning pattern
		for _, ports := range sourcePortsByHost[srcIP] {
			if len(ports) < 3 { // Need at least 3 ports to detect a pattern
				continue
			}

			// Sort ports
			sort.Ints(ports)

			// Count sequential ports (allowing small gaps)
			sequentialCount := 1
			maxSequential := 1
			for i := 1; i < len(ports); i++ {
				if ports[i] <= ports[i-1]+3 { // Allow gaps of up to 2 ports
					sequentialCount++
					if sequentialCount > maxSequential {
						maxSequential = sequentialCount
					}
				} else {
					sequentialCount = 1
				}
			}

			if float64(maxSequential) >= r.scanPatternThreshold {
				return true, nil
			}
		}
	}

	return false, nil
}

// HolidayPattern represents different types of holiday traffic patterns
type HolidayPattern string

const (
	PatternNormal     HolidayPattern = "normal"     // Normal business day pattern
	PatternReduced    HolidayPattern = "reduced"    // Reduced traffic (e.g. Christmas Day)
	PatternElevated   HolidayPattern = "elevated"   // Higher traffic (e.g. Cyber Monday)
	PatternAfterHours HolidayPattern = "afterhours" // After-hours pattern
)

// TimeBasedAnomalyRule detects unusual activity based on time patterns
type TimeBasedAnomalyRule struct {
	BaseRule
	startHour         int
	endHour           int
	weekendMultiplier float64
	timezone          *time.Location
	holidayCache      *HolidayCache
	cacheDir          string
	// New fields for improved pattern recognition
	transitionWindow  time.Duration // Window before/after holidays/weekends
	seasonalFactors   map[time.Month]float64
	weekdayFactors    map[time.Weekday]float64
	hourlyMultipliers map[int]float64
}

// NewTimeBasedAnomalyRule creates a new time-based anomaly detection rule
func NewTimeBasedAnomalyRule(id string, startHour, endHour int, weekendMultiplier float64, timezone string, cacheDir string) (*TimeBasedAnomalyRule, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone: %v", err)
	}

	cache, err := LoadCache(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load holiday cache: %v", err)
	}

	// Initialize seasonal factors (example values)
	seasonalFactors := map[time.Month]float64{
		time.January:   1.1, // Higher traffic in winter months
		time.February:  1.1,
		time.March:     1.0, // Normal traffic in spring
		time.April:     1.0,
		time.May:       0.9,
		time.June:      0.8, // Lower traffic in summer months
		time.July:      0.8,
		time.August:    0.8,
		time.September: 1.0,
		time.October:   1.0,
		time.November:  1.1,
		time.December:  1.2, // Higher traffic in December
	}

	// Initialize weekday factors
	weekdayFactors := map[time.Weekday]float64{
		time.Monday:    1.1, // Higher traffic on Mondays
		time.Tuesday:   1.0,
		time.Wednesday: 1.0,
		time.Thursday:  1.0,
		time.Friday:    0.9, // Lower traffic on Fridays
		time.Saturday:  1.0, // Weekend baseline same as weekday
		time.Sunday:    1.0,
	}

	// Initialize hourly multipliers
	hourlyMultipliers := make(map[int]float64)
	for hour := 0; hour < 24; hour++ {
		switch {
		case hour < 6: // Early morning
			hourlyMultipliers[hour] = 0.3
		case hour < startHour: // Before business hours
			hourlyMultipliers[hour] = 0.5
		case hour < 12: // Morning business hours
			hourlyMultipliers[hour] = 1.0
		case hour < 14: // Lunch hours
			hourlyMultipliers[hour] = 1.0 // Keep same as business hours
		case hour < endHour: // Afternoon business hours
			hourlyMultipliers[hour] = 1.0
		case hour < 20: // Evening hours
			hourlyMultipliers[hour] = 0.7
		default: // Late night
			hourlyMultipliers[hour] = 0.4
		}
	}

	return &TimeBasedAnomalyRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Time-based Activity Detection",
			description: "Detects unusual activity based on time patterns",
			category:    CategoryTimeAnomaly,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		startHour:         startHour,
		endHour:           endHour,
		weekendMultiplier: weekendMultiplier,
		timezone:          loc,
		holidayCache:      cache,
		cacheDir:          cacheDir,
		transitionWindow:  6 * time.Hour,
		seasonalFactors:   seasonalFactors,
		weekdayFactors:    weekdayFactors,
		hourlyMultipliers: hourlyMultipliers,
	}, nil
}

// Evaluate implements the main evaluation logic.
// This method uses the production clock and is the only public entry point.
func (r *TimeBasedAnomalyRule) Evaluate(ctx *DetectionContext) bool {
	// Get the production clock
	c := clockFactory()

	// Get current time in the rule's timezone
	now := c.now().In(r.timezone)
	currentDate := now.Format("2006-01-02")

	// Check if cache needs refresh
	if r.holidayCache.IsExpired() {
		if err := r.holidayCache.RefreshCache(r.cacheDir); err != nil {
			fmt.Printf("Failed to refresh holiday cache: %v\n", err)
		}
	}

	// Check if it's a holiday
	if holiday, exists := r.holidayCache.GetHoliday(currentDate); exists {
		return r.evaluateHolidayTraffic(ctx, holiday, c)
	}

	// Check if it's a weekend
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		return r.evaluateWeekendTraffic(ctx, c)
	}

	// Regular business day evaluation
	return r.evaluateBusinessDayTraffic(ctx, now.Hour(), c)
}

func (r *TimeBasedAnomalyRule) evaluateWeekendTraffic(ctx *DetectionContext, c clock) bool {
	totalConnections := uint64(0)
	for _, count := range ctx.CurrentSnapshot.ActiveConnections {
		totalConnections += count
	}

	patterns, ok := ctx.Metadata["activity_patterns"].(map[string]float64)
	if !ok {
		return false
	}

	// Calculate average baseline for business hours
	var businessHoursBaseline float64
	var count int
	for hour := r.startHour; hour < r.endHour; hour++ {
		hourStr := fmt.Sprintf("%02d", hour)
		if value, exists := patterns[hourStr]; exists {
			businessHoursBaseline += value
			count++
		}
	}

	if count == 0 {
		return false
	}
	businessHoursBaseline /= float64(count)

	// Get current time for adjustments
	now := c.now().In(r.timezone)

	// Apply seasonal and hourly adjustments
	seasonalFactor := r.seasonalFactors[now.Month()]
	hourlyFactor := r.hourlyMultipliers[now.Hour()]

	// Calculate base threshold with seasonal and hourly adjustments
	baseThreshold := businessHoursBaseline * seasonalFactor * hourlyFactor

	// Then apply weekend multiplier to get the maximum allowed traffic
	weekendThreshold := baseThreshold * r.weekendMultiplier

	// Compare total connections to weekend threshold
	return float64(totalConnections) > weekendThreshold
}

func (r *TimeBasedAnomalyRule) evaluateHolidayTraffic(ctx *DetectionContext, holiday HolidayInfo, c clock) bool {
	// Get current time in the rule's timezone
	now := c.now().In(r.timezone)
	currentDate := now.Format("2006-01-02")

	// Parse holiday date to check if we're actually on the holiday
	_, err := time.Parse("2006-01-02", holiday.Date)
	if err != nil {
		return false
	}

	// Verify we're evaluating the correct date
	if currentDate != holiday.Date {
		return false
	}

	// Calculate total connections
	totalConnections := uint64(0)
	for _, count := range ctx.CurrentSnapshot.ActiveConnections {
		totalConnections += count
	}

	patterns, ok := ctx.Metadata["activity_patterns"].(map[string]float64)
	if !ok {
		return false
	}

	// Calculate business hours baseline
	var businessHoursBaseline float64
	var count int
	for hour := r.startHour; hour < r.endHour; hour++ {
		hourStr := fmt.Sprintf("%02d", hour)
		if value, exists := patterns[hourStr]; exists {
			businessHoursBaseline += value
			count++
		}
	}

	if count == 0 {
		return false
	}
	businessHoursBaseline /= float64(count)

	// Get seasonal and hourly adjustments
	seasonalFactor := r.seasonalFactors[now.Month()]
	hourlyFactor := r.hourlyMultipliers[now.Hour()]

	// Calculate adjusted baseline
	adjustedBaseline := businessHoursBaseline * seasonalFactor * hourlyFactor

	// Determine thresholds based on pattern
	var threshold float64
	switch HolidayPattern(holiday.TrafficPattern) {
	case PatternReduced:
		threshold = adjustedBaseline // Alert if traffic is above normal baseline
	case PatternElevated:
		threshold = adjustedBaseline * 2.0 // Double traffic
	case PatternAfterHours:
		threshold = adjustedBaseline * 1.5 // 50% increase
	default:
		threshold = adjustedBaseline // Normal traffic
	}

	// For reduced patterns, alert if traffic is above normal baseline
	if HolidayPattern(holiday.TrafficPattern) == PatternReduced {
		return float64(totalConnections) > threshold
	}

	// For elevated/after-hours patterns, alert if traffic exceeds threshold
	return float64(totalConnections) > threshold
}

func (r *TimeBasedAnomalyRule) evaluateBusinessDayTraffic(ctx *DetectionContext, hour int, c clock) bool {
	if hour < r.startHour || hour >= r.endHour {
		return r.evaluateAfterHoursTraffic(ctx, c)
	}

	totalConnections := uint64(0)
	for _, count := range ctx.CurrentSnapshot.ActiveConnections {
		totalConnections += count
	}

	patterns, ok := ctx.Metadata["activity_patterns"].(map[string]float64)
	if !ok {
		return false
	}

	hourStr := fmt.Sprintf("%02d", hour)
	expectedActivity, exists := patterns[hourStr]
	if !exists {
		return false
	}

	// Get current time for adjustments
	now := c.now().In(r.timezone)

	// Apply seasonal and weekday adjustments
	seasonalFactor := r.seasonalFactors[now.Month()]
	weekdayFactor := r.weekdayFactors[now.Weekday()]
	hourlyFactor := r.hourlyMultipliers[hour]

	// Calculate adjusted threshold
	adjustedBaseline := expectedActivity * seasonalFactor * weekdayFactor * hourlyFactor
	businessThreshold := adjustedBaseline * 1.5 // Alert if 50% above adjusted baseline

	return float64(totalConnections) > businessThreshold
}

func (r *TimeBasedAnomalyRule) evaluateAfterHoursTraffic(ctx *DetectionContext, c clock) bool {
	totalConnections := uint64(0)
	for _, count := range ctx.CurrentSnapshot.ActiveConnections {
		totalConnections += count
	}

	patterns, ok := ctx.Metadata["activity_patterns"].(map[string]float64)
	if !ok {
		return false
	}

	// Calculate average baseline
	var baselineAvg float64
	for _, value := range patterns {
		baselineAvg += value
	}
	baselineAvg /= float64(len(patterns))

	// Get current time for adjustments
	now := c.now().In(r.timezone)

	// Apply seasonal and weekday adjustments
	seasonalFactor := r.seasonalFactors[now.Month()]
	weekdayFactor := r.weekdayFactors[now.Weekday()]
	hourlyFactor := r.hourlyMultipliers[now.Hour()]

	// Calculate adjusted threshold for after-hours
	adjustedBaseline := baselineAvg * seasonalFactor * weekdayFactor * hourlyFactor
	afterHoursThreshold := adjustedBaseline * 2.0 // More lenient threshold for after-hours

	return float64(totalConnections) > afterHoursThreshold
}

// GetHolidayCache returns the rule's holiday cache
func (r *TimeBasedAnomalyRule) GetHolidayCache() *HolidayCache {
	return r.holidayCache
}

// SetHolidayCache sets the rule's holiday cache
func (r *TimeBasedAnomalyRule) SetHolidayCache(cache *HolidayCache) {
	r.holidayCache = cache
}

// GeographicAnomalyRule detects connections from unusual locations
type GeographicAnomalyRule struct {
	BaseRule
	allowedCountries   map[string]bool // List of allowed countries
	allowedASNs        map[int]bool    // List of allowed Autonomous System Numbers
	unknownIPThreshold float64         // Threshold for connections from unknown locations
}

func NewGeographicAnomalyRule(id string, allowedCountries []string, allowedASNs []int, unknownIPThreshold float64) *GeographicAnomalyRule {
	countriesMap := make(map[string]bool)
	for _, country := range allowedCountries {
		countriesMap[country] = true
	}

	asnsMap := make(map[int]bool)
	for _, asn := range allowedASNs {
		asnsMap[asn] = true
	}

	return &GeographicAnomalyRule{
		BaseRule: BaseRule{
			id:          id,
			name:        "Geographic Location Detection",
			description: "Detects connections from unusual geographic locations",
			category:    CategoryGeoAnomaly,
			severity:    SeverityWarning,
			enabled:     true,
			metadata:    make(map[string]interface{}),
		},
		allowedCountries:   countriesMap,
		allowedASNs:        asnsMap,
		unknownIPThreshold: unknownIPThreshold,
	}
}

func (r *GeographicAnomalyRule) Evaluate(ctx *DetectionContext) (bool, error) {
	unknownCount := 0
	totalConnections := 0

	// Get IP geolocation data from metadata
	geoData, ok := ctx.Metadata["ip_geolocation"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	// Check each active connection
	for connKey, count := range ctx.CurrentSnapshot.ActiveConnections {
		totalConnections += int(count)

		// Extract source IP from connection key
		srcIP := strings.Split(connKey, "->")[0]
		srcIP = strings.Split(srcIP, ":")[0]

		// Get location data for this IP
		ipInfo, ok := geoData[srcIP].(map[string]interface{})
		if !ok {
			unknownCount += int(count)
			continue
		}

		// Check if connection is from allowed country/ASN
		country, ok1 := ipInfo["country"].(string)
		asn, ok2 := ipInfo["asn"].(int)

		if !ok1 || !ok2 || (!r.allowedCountries[country] && !r.allowedASNs[asn]) {
			unknownCount += int(count)
		}
	}

	// Calculate ratio of unknown/suspicious connections
	if totalConnections == 0 {
		return false, nil
	}

	unknownRatio := float64(unknownCount) / float64(totalConnections)
	return unknownRatio > r.unknownIPThreshold, nil
}
