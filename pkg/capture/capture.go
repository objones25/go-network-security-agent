package capture

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Config holds the configuration for packet capture
type Config struct {
	Interface   string
	Promiscuous bool
	SnapshotLen int32
	Timeout     time.Duration
	BPFFilter   string        // Berkeley Packet Filter expression
	StatsPeriod time.Duration // Period for statistics collection
	SampleRate  float64       // Percentage of packets to sample (0.0-1.0)
	RateLimit   int           // Maximum packets per second (0 for no limit)
}

// PacketStats holds statistics about captured packets
type PacketStats struct {
	mu                sync.RWMutex
	TotalPackets      uint64
	TotalBytes        uint64
	PacketsByProtocol map[string]uint64
	BytesByProtocol   map[string]uint64
	ActiveConnections map[string]uint64 // Source:Port -> Dest:Port connections
	LastUpdated       time.Time
}

// StatsSnapshot represents a point-in-time copy of statistics without mutex
type StatsSnapshot struct {
	TotalPackets      uint64
	TotalBytes        uint64
	PacketsByProtocol map[string]uint64
	BytesByProtocol   map[string]uint64
	ActiveConnections map[string]uint64
	LastUpdated       time.Time
}

// Packet represents a captured network packet with metadata
type Packet struct {
	Timestamp   time.Time
	Data        gopacket.Packet
	Source      string
	Destination string
	Protocol    string
	Length      int
	SrcPort     uint16
	DstPort     uint16
	IsInbound   bool
	Application string // Application layer protocol (HTTP, DNS, etc.)
}

// Engine defines the interface for packet capture operations
type Engine interface {
	Start(context.Context) error
	Stop() error
	Packets() <-chan Packet
	Stats() *PacketStats
	GetStats() StatsSnapshot
	UpdateStats(Packet)
	ResetStats()
	SetBPFFilter(filter string) error
	ShouldProcessPacket() bool // For testing rate limiting and sampling
}

// PCAPEngine implements the Engine interface using libpcap
type PCAPEngine struct {
	config     Config
	handle     *pcap.Handle
	packetChan chan Packet
	done       chan struct{}
	stats      *PacketStats
	logger     *log.Logger
	lastTick   time.Time  // For rate limiting
	tokens     float64    // Available tokens for rate limiting
	rng        *rand.Rand // For sampling
	mu         sync.Mutex // For rate limiting state
}

// NewPCAPEngine creates a new packet capture engine
func NewPCAPEngine(config Config) (*PCAPEngine, error) {
	// Set default values if not specified
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.StatsPeriod == 0 {
		config.StatsPeriod = 10 * time.Second
	}
	if config.SampleRate <= 0.0 {
		config.SampleRate = 0.0 // Ensure it's exactly 0.0
	} else if config.SampleRate > 1.0 {
		config.SampleRate = 1.0
	}

	return &PCAPEngine{
		config:     config,
		packetChan: make(chan Packet, 1000),
		done:       make(chan struct{}),
		stats: &PacketStats{
			PacketsByProtocol: make(map[string]uint64),
			BytesByProtocol:   make(map[string]uint64),
			ActiveConnections: make(map[string]uint64),
		},
		logger:   log.New(log.Writer(), "[PCAPEngine] ", log.LstdFlags),
		lastTick: time.Now(),
		tokens:   1.0, // Start with 1 token
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Start begins packet capture
func (e *PCAPEngine) Start(ctx context.Context) error {
	var err error
	e.handle, err = pcap.OpenLive(
		e.config.Interface,
		e.config.SnapshotLen,
		e.config.Promiscuous,
		e.config.Timeout,
	)
	if err != nil {
		return fmt.Errorf("error opening interface %s: %v", e.config.Interface, err)
	}

	// Apply BPF filter if specified
	if e.config.BPFFilter != "" {
		if err := e.SetBPFFilter(e.config.BPFFilter); err != nil {
			return err
		}
	}

	go e.capture(ctx)
	go e.collectStats(ctx)
	return nil
}

// SetBPFFilter applies a BPF filter to the capture
func (e *PCAPEngine) SetBPFFilter(filter string) error {
	if e.handle == nil {
		return fmt.Errorf("capture not started")
	}
	return e.handle.SetBPFFilter(filter)
}

// Stop ends packet capture
func (e *PCAPEngine) Stop() error {
	if e.handle != nil {
		e.handle.Close()
	}
	close(e.done)
	return nil
}

// Packets returns the channel of captured packets
func (e *PCAPEngine) Packets() <-chan Packet {
	return e.packetChan
}

// Stats returns current packet statistics
func (e *PCAPEngine) Stats() *PacketStats {
	return e.stats
}

// GetStats returns a copy of the current statistics without the mutex
func (e *PCAPEngine) GetStats() StatsSnapshot {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	// Create a deep copy of the stats
	snapshot := StatsSnapshot{
		TotalPackets: e.stats.TotalPackets,
		TotalBytes:   e.stats.TotalBytes,
		LastUpdated:  e.stats.LastUpdated,

		// Deep copy maps
		PacketsByProtocol: make(map[string]uint64, len(e.stats.PacketsByProtocol)),
		BytesByProtocol:   make(map[string]uint64, len(e.stats.BytesByProtocol)),
		ActiveConnections: make(map[string]uint64, len(e.stats.ActiveConnections)),
	}

	for k, v := range e.stats.PacketsByProtocol {
		snapshot.PacketsByProtocol[k] = v
	}
	for k, v := range e.stats.BytesByProtocol {
		snapshot.BytesByProtocol[k] = v
	}
	for k, v := range e.stats.ActiveConnections {
		snapshot.ActiveConnections[k] = v
	}

	return snapshot
}

// collectStats periodically updates packet statistics
func (e *PCAPEngine) collectStats(ctx context.Context) {
	ticker := time.NewTicker(e.config.StatsPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case <-ticker.C:
			if stats, err := e.handle.Stats(); err == nil {
				e.logger.Printf("Packets received: %d, dropped: %d", stats.PacketsReceived, stats.PacketsDropped)
			}
		}
	}
}

// UpdateStats updates packet statistics with a given packet
func (e *PCAPEngine) UpdateStats(packet Packet) {
	e.updateStats(packet)
}

// ResetStats resets all statistics to zero
func (e *PCAPEngine) ResetStats() {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	e.stats.TotalPackets = 0
	e.stats.TotalBytes = 0
	e.stats.LastUpdated = time.Now()
	e.stats.PacketsByProtocol = make(map[string]uint64)
	e.stats.BytesByProtocol = make(map[string]uint64)
	e.stats.ActiveConnections = make(map[string]uint64)
}

// updateStats updates packet statistics
func (e *PCAPEngine) updateStats(packet Packet) {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	e.stats.TotalPackets++
	e.stats.TotalBytes += uint64(packet.Length)
	e.stats.PacketsByProtocol[packet.Protocol]++
	e.stats.BytesByProtocol[packet.Protocol] += uint64(packet.Length)

	// Track connections
	connKey := fmt.Sprintf("%s:%d->%s:%d", packet.Source, packet.SrcPort, packet.Destination, packet.DstPort)
	e.stats.ActiveConnections[connKey]++

	e.stats.LastUpdated = time.Now()
}

// ShouldProcessPacket determines if a packet should be processed based on sampling and rate limiting
func (e *PCAPEngine) ShouldProcessPacket() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check sampling rate first
	if e.config.SampleRate == 0.0 {
		return false
	}
	if e.config.SampleRate < 1.0 && e.rng.Float64() >= e.config.SampleRate {
		return false
	}

	// No rate limit set
	if e.config.RateLimit <= 0 {
		return true
	}

	now := time.Now()
	if e.lastTick.IsZero() {
		e.lastTick = now
		e.tokens = 1.0 // Start with 1 token
		return true
	}

	elapsed := now.Sub(e.lastTick).Seconds()
	if elapsed >= 0.1 { // Only add tokens every 100ms
		// Calculate tokens to add based on rate and elapsed time
		tokensToAdd := float64(e.config.RateLimit) * elapsed // Tokens per second * seconds

		// Adjust max tokens based on sampling rate
		// When sampling is active (< 1.0), use smaller bucket to control combined rate
		// When no sampling (1.0), use larger bucket to achieve full rate
		maxTokens := float64(e.config.RateLimit) / 10.0 // Default 10% for no sampling
		if e.config.SampleRate < 1.0 {
			maxTokens = float64(e.config.RateLimit) / 20.0 // 5% for sampling
		}

		// Cap token addition and total tokens
		tokensToAdd = math.Min(tokensToAdd, maxTokens)
		e.tokens = math.Min(e.tokens+tokensToAdd, maxTokens)

		e.lastTick = now
	}

	if e.tokens < 1.0 {
		return false
	}

	e.tokens--
	return true
}

// capture is the main packet processing loop
func (e *PCAPEngine) capture(ctx context.Context) {
	defer close(e.packetChan)
	packetSource := gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				if !strings.Contains(err.Error(), "Timeout") {
					e.logger.Printf("Error capturing packet: %v", err)
				}
				continue
			}

			// Apply sampling and rate limiting
			if !e.ShouldProcessPacket() {
				if e.config.RateLimit > 0 {
					e.logger.Printf("Packet dropped due to rate limiting")
				}
				continue
			}

			pkt := e.processPacket(packet)
			e.updateStats(pkt)
			e.packetChan <- pkt
		}
	}
}

// processPacket extracts information from a captured packet
func (e *PCAPEngine) processPacket(packet gopacket.Packet) Packet {
	var srcPort, dstPort uint16
	var src, dst, proto, app string
	var isInbound bool

	// Get IP layer info
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}
	if ipLayer != nil {
		switch v := ipLayer.(type) {
		case *layers.IPv4:
			src = v.SrcIP.String()
			dst = v.DstIP.String()
			proto = v.Protocol.String()
		case *layers.IPv6:
			src = v.SrcIP.String()
			dst = v.DstIP.String()
			proto = v.NextHeader.String()
		}
	}

	// Get TCP/UDP port info and determine application protocol
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "TCP"
		app = determineApplication(srcPort, dstPort)
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			proto = "UDP"
			app = determineApplication(srcPort, dstPort)
		}
	}

	// Format source and destination with ports
	if srcPort > 0 {
		src = fmt.Sprintf("%s:%d", src, srcPort)
	}
	if dstPort > 0 {
		dst = fmt.Sprintf("%s:%d", dst, dstPort)
	}

	// Determine if packet is inbound
	isInbound = dstPort <= 1024 || (dstPort == 8080) // Add more port logic as needed

	return Packet{
		Timestamp:   packet.Metadata().Timestamp,
		Data:        packet,
		Source:      src,
		Destination: dst,
		Protocol:    proto,
		Length:      len(packet.Data()),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		IsInbound:   isInbound,
		Application: app,
	}
}

// determineApplication identifies the application protocol based on port numbers
func determineApplication(srcPort, dstPort uint16) string {
	ports := map[uint16]string{
		80:    "HTTP",
		443:   "HTTPS",
		53:    "DNS",
		22:    "SSH",
		21:    "FTP",
		25:    "SMTP",
		110:   "POP3",
		143:   "IMAP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
		8080:  "HTTP-ALT",
	}

	if app, ok := ports[dstPort]; ok {
		return app
	}
	if app, ok := ports[srcPort]; ok {
		return app
	}
	return "UNKNOWN"
}
