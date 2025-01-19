package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/agent.yaml", "path to configuration file")
	flag.Parse()

	// TODO: Load configuration from configPath
	log.Printf("Using configuration file: %s", *configPath)

	// For now, using hardcoded config
	config := capture.Config{
		Interface:   "en0", // Default interface for macOS
		Promiscuous: true,
		SnapshotLen: 65535,
		Timeout:     time.Second,
	}

	// Initialize packet capture engine
	engine, err := capture.NewPCAPEngine(config)
	if err != nil {
		log.Fatalf("Failed to create packet capture engine: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start packet capture
	if err := engine.Start(ctx); err != nil {
		log.Fatalf("Failed to start packet capture: %v", err)
	}
	defer engine.Stop()

	log.Printf("Network Security Agent starting on interface %s...", config.Interface)

	// Start packet processing
	go processPackets(engine.Packets())

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)
}

func processPackets(packets <-chan capture.Packet) {
	for packet := range packets {
		log.Printf("Packet: src=%s dst=%s proto=%s len=%d",
			packet.Source,
			packet.Destination,
			packet.Protocol,
			packet.Length,
		)
	}
}
