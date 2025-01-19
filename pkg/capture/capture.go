package capture

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand"
	"runtime"
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
	NumWorkers  int           // Number of worker goroutines for packet processing
	BatchSize   int           // Size of packet batches for processing
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

	// Performance metrics
	ProcessingLatency time.Duration // Average processing time per packet
	BatchLatency      time.Duration // Average processing time per batch
	DroppedPackets    uint64        // Packets dropped due to backpressure
	SampledPackets    uint64        // Packets dropped due to sampling
	RateLimitDrops    uint64        // Packets dropped due to rate limiting
	WorkerUtilization []float64     // Per-worker utilization
	BatchSizes        []int         // Recent batch sizes for monitoring
	ChannelBacklog    int           // Current number of pending packets
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
	lastTick   time.Time    // For rate limiting
	tokens     float64      // Available tokens for rate limiting
	rng        *rand.Rand   // For sampling
	mu         sync.Mutex   // For rate limiting state
	handleMu   sync.RWMutex // For pcap handle synchronization

	// Worker pool management
	workerWg  sync.WaitGroup
	batchChan chan []gopacket.Packet
	errChan   chan error
	batchPool sync.Pool

	// Worker timing tracking
	workerStartTimes []time.Time
	workerMu         sync.RWMutex

	// Adaptive batch sizing
	currentBatchSize int
	batchSizeMu      sync.RWMutex
	lastAdjustment   time.Time
	adjustmentStats  struct {
		processingLatency time.Duration
		channelBacklog    int
		workerUtilization float64
	}
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
	if config.NumWorkers <= 0 {
		config.NumWorkers = runtime.NumCPU() // Default to number of CPU cores
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 100 // Default batch size
	}

	engine := &PCAPEngine{
		config:     config,
		packetChan: make(chan Packet, 1000),
		done:       make(chan struct{}),
		stats: &PacketStats{
			PacketsByProtocol: make(map[string]uint64),
			BytesByProtocol:   make(map[string]uint64),
			ActiveConnections: make(map[string]uint64),
			WorkerUtilization: make([]float64, config.NumWorkers),
		},
		logger:           log.New(log.Writer(), "[PCAPEngine] ", log.LstdFlags),
		lastTick:         time.Now(),
		tokens:           1.0,
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
		batchChan:        make(chan []gopacket.Packet, config.NumWorkers),
		errChan:          make(chan error, config.NumWorkers),
		currentBatchSize: config.BatchSize,
		lastAdjustment:   time.Now(),
		workerStartTimes: make([]time.Time, config.NumWorkers),
	}

	// Initialize batch pool
	engine.batchPool.New = func() interface{} {
		slice := make([]gopacket.Packet, 0, config.BatchSize*2) // Extra capacity for growth
		return &slice
	}

	return engine, nil
}

// Start begins packet capture
func (e *PCAPEngine) Start(ctx context.Context) error {
	e.handleMu.Lock()
	defer e.handleMu.Unlock()

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
			e.handle.Close()
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
	e.handleMu.Lock()
	defer e.handleMu.Unlock()

	if e.handle != nil {
		e.handle.Close()
		e.handle = nil
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
			e.handleMu.RLock()
			if e.handle != nil {
				if stats, err := e.handle.Stats(); err == nil {
					e.logger.Printf("Packets received: %d, dropped: %d", stats.PacketsReceived, stats.PacketsDropped)
				}
			}
			e.handleMu.RUnlock()
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
	e.stats.DroppedPackets = 0
	e.stats.SampledPackets = 0
	e.stats.RateLimitDrops = 0
	e.stats.ProcessingLatency = 0
	e.stats.BatchLatency = 0
	e.stats.ChannelBacklog = 0
	e.stats.BatchSizes = e.stats.BatchSizes[:0] // Clear batch sizes slice

	// Reset maps
	e.stats.PacketsByProtocol = make(map[string]uint64)
	e.stats.BytesByProtocol = make(map[string]uint64)
	e.stats.ActiveConnections = make(map[string]uint64)

	// Reset worker utilization
	for i := range e.stats.WorkerUtilization {
		e.stats.WorkerUtilization[i] = 0
	}

	// Reset worker start times
	e.workerMu.Lock()
	for i := range e.workerStartTimes {
		e.workerStartTimes[i] = time.Time{} // Zero value
	}
	e.workerMu.Unlock()
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
		maxTokens := float64(e.config.RateLimit) / 8.0 // Default 12.5% for no sampling
		if e.config.SampleRate < 1.0 {
			maxTokens = float64(e.config.RateLimit) / 16.0 // 6.25% for sampling
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

// adjustBatchSize dynamically adjusts the batch size based on performance metrics
func (e *PCAPEngine) adjustBatchSize() {
	e.batchSizeMu.Lock()
	defer e.batchSizeMu.Unlock()

	// Only adjust every 2 seconds (more frequent than before)
	if time.Since(e.lastAdjustment) < 2*time.Second {
		return
	}

	e.stats.mu.RLock()
	latency := e.stats.ProcessingLatency
	backlog := e.stats.ChannelBacklog
	var avgUtilization float64
	for _, u := range e.stats.WorkerUtilization {
		avgUtilization += u
	}
	if len(e.stats.WorkerUtilization) > 0 {
		avgUtilization /= float64(len(e.stats.WorkerUtilization))
	}
	e.stats.mu.RUnlock()

	// Store current stats for trend analysis
	prevStats := e.adjustmentStats
	e.adjustmentStats.processingLatency = latency
	e.adjustmentStats.channelBacklog = backlog
	e.adjustmentStats.workerUtilization = avgUtilization

	// More aggressive batch size adjustments
	targetBatchSize := e.currentBatchSize

	// Multi-level adjustment based on conditions
	switch {
	case latency > 50*time.Millisecond || backlog > 100:
		// Severe conditions - aggressive reduction
		targetBatchSize = int(float64(targetBatchSize) * 0.5)
	case latency > 20*time.Millisecond || backlog > 50:
		// Moderate conditions - medium reduction
		targetBatchSize = int(float64(targetBatchSize) * 0.7)
	case latency > 10*time.Millisecond || backlog > 20:
		// Mild conditions - slight reduction
		targetBatchSize = int(float64(targetBatchSize) * 0.9)
	case avgUtilization < 0.3:
		// Very low utilization - aggressive increase
		targetBatchSize = int(float64(targetBatchSize) * 1.5)
	case avgUtilization < 0.5:
		// Low utilization - moderate increase
		targetBatchSize = int(float64(targetBatchSize) * 1.3)
	case avgUtilization < 0.7 && latency <= time.Duration(float64(prevStats.processingLatency)*1.05):
		// Room for growth - slight increase
		targetBatchSize = int(float64(targetBatchSize) * 1.1)
	}

	// Enforce min/max bounds
	minBatchSize := 10
	maxBatchSize := e.config.BatchSize * 4 // Allow for larger maximum
	if targetBatchSize < minBatchSize {
		targetBatchSize = minBatchSize
	}
	if targetBatchSize > maxBatchSize {
		targetBatchSize = maxBatchSize
	}

	// Ensure minimum change in high stress scenarios
	if targetBatchSize == e.currentBatchSize && (latency > 5*time.Millisecond || backlog > 10) {
		targetBatchSize = int(float64(e.currentBatchSize) * 0.95) // Minimum 5% reduction
	}

	// Update batch size if changed
	if targetBatchSize != e.currentBatchSize {
		e.logger.Printf("Adjusting batch size from %d to %d (latency: %v, backlog: %d, utilization: %.2f)",
			e.currentBatchSize, targetBatchSize, latency, backlog, avgUtilization)
		e.currentBatchSize = targetBatchSize
	}

	e.lastAdjustment = time.Now()
}

// getCurrentBatchSize returns the current adaptive batch size
func (e *PCAPEngine) getCurrentBatchSize() int {
	e.batchSizeMu.RLock()
	defer e.batchSizeMu.RUnlock()
	return e.currentBatchSize
}

// capture is the main packet processing loop
func (e *PCAPEngine) capture(ctx context.Context) {
	defer func() {
		close(e.packetChan)
		close(e.batchChan)
		close(e.errChan)
	}()

	// Start worker pool
	e.startWorkers(ctx)

	e.handleMu.RLock()
	if e.handle == nil {
		e.handleMu.RUnlock()
		e.logger.Printf("Error: pcap handle is nil")
		return
	}

	linkType := e.handle.LinkType()
	packetSource := gopacket.NewPacketSource(e.handle, linkType)
	e.handleMu.RUnlock()

	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Get initial batch from pool
	batchPtr := e.batchPool.Get().(*[]gopacket.Packet)
	batch := (*batchPtr)[:0]

	batchTimer := time.NewTicker(100 * time.Millisecond)
	adjustTimer := time.NewTicker(1 * time.Second)
	defer batchTimer.Stop()
	defer adjustTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			e.batchPool.Put(batchPtr)
			return
		case <-e.done:
			e.batchPool.Put(batchPtr)
			return
		case <-adjustTimer.C:
			e.adjustBatchSize()
		case err := <-e.errChan:
			if err != nil {
				e.logger.Printf("Worker error: %v", err)
			}
			continue
		case <-batchTimer.C:
			if len(batch) > 0 {
				select {
				case e.batchChan <- batch:
					batchPtr = e.batchPool.Get().(*[]gopacket.Packet)
					batch = (*batchPtr)[:0]
				case <-ctx.Done():
					e.batchPool.Put(batchPtr)
					return
				case <-e.done:
					e.batchPool.Put(batchPtr)
					return
				}
			}
		default:
			e.handleMu.RLock()
			if e.handle == nil {
				e.handleMu.RUnlock()
				e.batchPool.Put(batchPtr)
				return
			}
			packet, err := packetSource.NextPacket()
			e.handleMu.RUnlock()

			if err != nil {
				if !strings.Contains(err.Error(), "Timeout") {
					e.logger.Printf("Error capturing packet: %v", err)
				}
				continue
			}

			batch = append(batch, packet)
			currentBatchSize := e.getCurrentBatchSize()

			if len(batch) >= currentBatchSize {
				select {
				case e.batchChan <- batch:
					batchPtr = e.batchPool.Get().(*[]gopacket.Packet)
					batch = (*batchPtr)[:0]
				case <-ctx.Done():
					e.batchPool.Put(batchPtr)
					return
				case <-e.done:
					e.batchPool.Put(batchPtr)
					return
				}
			}
		}
	}
}

// startWorkers initializes and starts the worker pool
func (e *PCAPEngine) startWorkers(ctx context.Context) {
	for i := 0; i < e.config.NumWorkers; i++ {
		e.workerWg.Add(1)
		go e.worker(ctx, i)
	}

	// Start cleanup goroutine
	go func() {
		<-ctx.Done()
		e.workerWg.Wait()
	}()
}

// updateMetrics updates performance metrics with improved worker utilization tracking
func (e *PCAPEngine) updateMetrics(start time.Time, batchSize int, processed int, workerId int) {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	elapsed := time.Since(start)

	// Update worker utilization based on actual elapsed time
	e.workerMu.Lock()
	activeTime := elapsed
	if !e.workerStartTimes[workerId].IsZero() {
		activeTime = time.Since(e.workerStartTimes[workerId])
	}
	// Calculate utilization based on actual elapsed time since start
	utilization := float64(activeTime) / float64(time.Second) // Use 1 second as baseline
	if utilization > 1.0 {
		utilization = 1.0
	}
	e.stats.WorkerUtilization[workerId] = utilization
	e.workerStartTimes[workerId] = time.Now() // Update start time for next cycle
	e.workerMu.Unlock()

	// Update processing latencies
	if processed > 0 {
		// Update per-packet latency
		newLatency := elapsed / time.Duration(processed)
		if e.stats.ProcessingLatency == 0 {
			e.stats.ProcessingLatency = newLatency
		} else {
			// Exponential moving average
			e.stats.ProcessingLatency = (e.stats.ProcessingLatency*9 + newLatency) / 10
		}
	}

	// Update batch latency
	if e.stats.BatchLatency == 0 {
		e.stats.BatchLatency = elapsed
	} else {
		e.stats.BatchLatency = (e.stats.BatchLatency*9 + elapsed) / 10
	}

	// Update batch size history
	e.stats.BatchSizes = append(e.stats.BatchSizes, batchSize)
	if len(e.stats.BatchSizes) > 100 {
		e.stats.BatchSizes = e.stats.BatchSizes[1:]
	}

	// Update channel backlog
	e.stats.ChannelBacklog = len(e.packetChan)
}

// worker processes packets in a single worker goroutine
func (e *PCAPEngine) worker(ctx context.Context, id int) {
	defer e.workerWg.Done()
	workerLogger := log.New(e.logger.Writer(), fmt.Sprintf("[PCAPEngine Worker-%d] ", id), log.LstdFlags)

	for {
		select {
		case <-ctx.Done():
			workerLogger.Printf("Worker shutting down")
			return
		case batch, ok := <-e.batchChan:
			if !ok {
				workerLogger.Printf("Batch channel closed, worker shutting down")
				return
			}

			start := time.Now()
			processed := 0
			sampledDrops := 0
			rateLimitDrops := 0

			// Process batch of packets
			for _, packet := range batch {
				if !e.ShouldProcessPacket() {
					if e.config.SampleRate < 1.0 {
						sampledDrops++
					} else {
						rateLimitDrops++
					}
					continue
				}

				pkt := e.processPacket(packet)
				e.updateStats(pkt)
				processed++

				select {
				case e.packetChan <- pkt:
				case <-ctx.Done():
					workerLogger.Printf("Context cancelled while processing batch")
					e.batchPool.Put(&batch)
					return
				default: // Channel full - update dropped packets metric
					e.stats.mu.Lock()
					e.stats.DroppedPackets++
					e.stats.mu.Unlock()
				}
			}

			// Update metrics
			e.updateMetrics(start, len(batch), processed, id)

			// Update sampling and rate limiting metrics
			e.stats.mu.Lock()
			e.stats.SampledPackets += uint64(sampledDrops)
			e.stats.RateLimitDrops += uint64(rateLimitDrops)
			e.stats.mu.Unlock()

			workerLogger.Printf("Processed %d/%d packets (sampled: %d, rate limited: %d) in %v",
				processed, len(batch), sampledDrops, rateLimitDrops, time.Since(start))

			// Return batch to pool
			e.batchPool.Put(&batch)
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

// GetMetrics returns current performance metrics
func (e *PCAPEngine) GetMetrics() map[string]interface{} {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	metrics := map[string]interface{}{
		"processing_latency_ns": e.stats.ProcessingLatency.Nanoseconds(),
		"batch_latency_ns":      e.stats.BatchLatency.Nanoseconds(),
		"dropped_packets":       e.stats.DroppedPackets,
		"sampled_packets":       e.stats.SampledPackets,
		"rate_limit_drops":      e.stats.RateLimitDrops,
		"channel_backlog":       e.stats.ChannelBacklog,
		"worker_utilization":    make([]float64, len(e.stats.WorkerUtilization)),
		"avg_batch_size":        0,
		"current_batch_size":    e.currentBatchSize,
	}

	// Copy worker utilization
	copy(metrics["worker_utilization"].([]float64), e.stats.WorkerUtilization)

	// Calculate average batch size as integer
	if len(e.stats.BatchSizes) > 0 {
		var sum int
		for _, size := range e.stats.BatchSizes {
			sum += size
		}
		metrics["avg_batch_size"] = sum / len(e.stats.BatchSizes)
	}

	return metrics
}

// AdjustBatchSize dynamically adjusts the batch size based on performance metrics
// Exported for testing
func (e *PCAPEngine) AdjustBatchSize() {
	e.adjustBatchSize()
}

// GetCurrentBatchSize returns the current adaptive batch size
// Exported for testing
func (e *PCAPEngine) GetCurrentBatchSize() int {
	return e.getCurrentBatchSize()
}

// UpdateMetrics updates performance metrics
// Exported for testing
func (e *PCAPEngine) UpdateMetrics(start time.Time, batchSize int, processed int, workerId int) {
	e.updateMetrics(start, batchSize, processed, workerId)
}

// GetBatchFromPool gets a new batch from the memory pool
// Exported for testing
func (e *PCAPEngine) GetBatchFromPool() *[]gopacket.Packet {
	return e.batchPool.Get().(*[]gopacket.Packet)
}

// ReturnBatchToPool returns a batch to the memory pool
// Exported for testing
func (e *PCAPEngine) ReturnBatchToPool(batch *[]gopacket.Packet) {
	e.batchPool.Put(batch)
}

// SetLastAdjustmentTime sets the last adjustment time - exported for testing only
func (e *PCAPEngine) SetLastAdjustmentTime(t time.Time) {
	e.batchSizeMu.Lock()
	defer e.batchSizeMu.Unlock()
	e.lastAdjustment = t
}
