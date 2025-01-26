package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/objones25/go-network-security-agent/pkg/alert"
	"github.com/objones25/go-network-security-agent/pkg/anomaly"
	"github.com/objones25/go-network-security-agent/pkg/baseline"
	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/objones25/go-network-security-agent/pkg/dashboard"
)

type Config struct {
	Agent struct {
		Name      string `yaml:"name"`
		Interface string `yaml:"interface"`
		LogLevel  string `yaml:"log_level"`
	} `yaml:"agent"`
	Capture struct {
		Promiscuous bool   `yaml:"promiscuous"`
		SnapshotLen int32  `yaml:"snapshot_len"`
		Timeout     string `yaml:"timeout"`
	} `yaml:"capture"`
	Baseline struct {
		InitialLearningPeriod string `yaml:"initial_learning_period"`
		UpdateInterval        string `yaml:"update_interval"`
		MinSamples            int    `yaml:"min_samples"`
	} `yaml:"baseline"`
	Alerts struct {
		Critical struct {
			Notification bool `yaml:"notification"`
			Desktop      bool `yaml:"desktop"`
			Log          bool `yaml:"log"`
		} `yaml:"critical"`
		Warning struct {
			Notification bool `yaml:"notification"`
			Desktop      bool `yaml:"desktop"`
			Log          bool `yaml:"log"`
		} `yaml:"warning"`
		Info struct {
			Notification bool `yaml:"notification"`
			Desktop      bool `yaml:"desktop"`
			Log          bool `yaml:"log"`
		} `yaml:"info"`
		Email struct {
			Enabled    bool     `yaml:"enabled"`
			Server     string   `yaml:"server"`
			Port       int      `yaml:"port"`
			Username   string   `yaml:"username"`
			Recipients []string `yaml:"recipients"`
			FromEmail  string   `yaml:"from_email"`
		} `yaml:"email"`
	} `yaml:"alerts"`
	Dashboard struct {
		Port             int    `yaml:"port"`
		MetricsRetention string `yaml:"metrics_retention"`
		UpdateInterval   string `yaml:"update_interval"`
	} `yaml:"dashboard"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Replace environment variables in the config file
	content := string(data)
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) != 2 {
			continue
		}
		placeholder := "${" + pair[0] + "}"
		content = strings.ReplaceAll(content, placeholder, pair[1])
	}

	var config Config
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	return &config, nil
}

func checkRoot() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %v", err)
	}
	if currentUser.Uid != "0" {
		log.Fatal("This program requires root privileges. Please run with sudo.")
	}
}

func loadEnvFile() error {
	// Read .env file
	data, err := os.ReadFile(".env")
	if err != nil {
		return fmt.Errorf("error reading .env file: %v", err)
	}

	// Parse each line
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first = sign
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Set environment variable if not already set
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return nil
}

func main() {
	// Load environment variables from .env file
	if err := loadEnvFile(); err != nil {
		log.Printf("Warning: Could not load .env file: %v", err)
	}

	// Parse command line flags
	configFile := flag.String("config", "config/agent.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Check for root privileges
	checkRoot()

	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting Network Security Agent (%s)...", config.Agent.Name)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse durations from config
	learningPeriod, err := time.ParseDuration(config.Baseline.InitialLearningPeriod)
	if err != nil {
		log.Fatalf("Invalid learning period: %v", err)
	}
	updateInterval, err := time.ParseDuration(config.Baseline.UpdateInterval)
	if err != nil {
		log.Fatalf("Invalid update interval: %v", err)
	}
	captureTimeout, err := time.ParseDuration(config.Capture.Timeout)
	if err != nil {
		log.Fatalf("Invalid capture timeout: %v", err)
	}

	// Initialize alert manager with notification settings
	var notifyConfig alert.NotificationConfig
	notifyConfig.Threshold = alert.PriorityHigh // Default threshold

	// Configure email notifications if enabled
	if config.Alerts.Email.Enabled {
		notifyConfig.Email = &alert.EmailConfig{
			Recipients: config.Alerts.Email.Recipients,
			SMTPServer: config.Alerts.Email.Server,
			SMTPPort:   config.Alerts.Email.Port,
			Username:   config.Alerts.Email.Username,
			Password:   os.Getenv("SMTP_PASSWORD"), // Get from environment variable
			FromEmail:  config.Alerts.Email.FromEmail,
		}
	}

	alertManager, err := alert.NewManager()
	if err != nil {
		log.Fatalf("Failed to create alert manager: %v", err)
	}

	// Configure notifications after creation
	if err := alertManager.ConfigureNotifications(notifyConfig); err != nil {
		log.Fatalf("Failed to configure alert notifications: %v", err)
	}

	// Initialize baseline manager
	baselineConfig := baseline.DefaultConfig()
	baselineConfig.InitialLearningPeriod = learningPeriod
	baselineConfig.UpdateInterval = updateInterval
	baselineConfig.MinSamples = config.Baseline.MinSamples

	baselineManager, err := baseline.NewManager(baselineConfig)
	if err != nil {
		log.Fatalf("Failed to create baseline manager: %v", err)
	}

	// Initialize anomaly detector
	anomalyDetector, err := anomaly.NewDetector(baselineManager)
	if err != nil {
		log.Fatalf("Failed to create anomaly detector: %v", err)
	}

	// Initialize packet capture
	packetCapture, err := capture.NewPCAPEngine(capture.Config{
		Interface:   config.Agent.Interface,
		Promiscuous: config.Capture.Promiscuous,
		SnapshotLen: config.Capture.SnapshotLen,
		Timeout:     captureTimeout,
		StatsPeriod: updateInterval,
		SampleRate:  1.0,
		RateLimit:   10000,
		NumWorkers:  4,
		BatchSize:   100,
	})
	if err != nil {
		log.Fatalf("Failed to create packet capture: %v", err)
	}

	// Start components in order
	components := []struct {
		name    string
		start   func(context.Context) error
		stop    func() error
		timeout time.Duration
	}{
		{"Alert Manager", alertManager.Start, alertManager.Stop, 5 * time.Second},
		{"Baseline Manager", baselineManager.Start, baselineManager.Stop, 5 * time.Second},
		{"Anomaly Detector", anomalyDetector.Start, anomalyDetector.Stop, 5 * time.Second},
		{"Packet Capture", packetCapture.Start, packetCapture.Stop, 10 * time.Second},
	}

	// Start each component
	for _, comp := range components {
		if err := comp.start(ctx); err != nil {
			log.Fatalf("Failed to start %s: %v", comp.name, err)
		}
		log.Printf("Started %s", comp.name)
	}

	// Start packet processing pipeline
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetCapture.Packets():
				if !ok {
					return
				}
				// Update packet stats
				packetCapture.UpdateStats(packet)

				// Get current stats snapshot
				stats := packetCapture.GetStats()

				// Update baseline stats
				baselineManager.AddMetrics(stats)

				// Check for anomalies
				if alerts := anomalyDetector.Detect(stats); len(alerts) > 0 {
					for _, alert := range alerts {
						enrichedAlert, err := alertManager.ProcessAlert(alert)
						if err != nil {
							log.Printf("Error processing alert: %v", err)
						} else {
							log.Printf("Generated alert: %s (priority: %s)", enrichedAlert.Message, enrichedAlert.Priority)
						}
					}
				}
			}
		}
	}()

	// Start dashboard server
	dashboardAddr := fmt.Sprintf(":%d", config.Dashboard.Port)
	dashboardServer := dashboard.NewDashboardServer(dashboardAddr, alertManager)
	go func() {
		if err := dashboardServer.Start(); err != nil {
			log.Printf("Dashboard server error: %v", err)
			cancel() // Cancel context to trigger shutdown
		}
	}()

	// Print startup information
	fmt.Printf("\nNetwork Security Agent Started\n")
	fmt.Printf("==============================\n")
	fmt.Printf("Name:             %s\n", config.Agent.Name)
	fmt.Printf("Dashboard:        http://localhost:%d\n", config.Dashboard.Port)
	fmt.Printf("Interface:        %s\n", config.Agent.Interface)
	fmt.Printf("Learning Period:  %s\n", config.Baseline.InitialLearningPeriod)
	fmt.Printf("Update Interval:  %s\n", config.Baseline.UpdateInterval)
	fmt.Printf("Press Ctrl+C to stop\n\n")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	log.Printf("Shutting down...")
	cancel()

	// Stop components in reverse order
	for i := len(components) - 1; i >= 0; i-- {
		comp := components[i]
		stopCtx, stopCancel := context.WithTimeout(context.Background(), comp.timeout)

		// Stop in a goroutine to respect timeout
		stopChan := make(chan error, 1)
		go func() {
			stopChan <- comp.stop()
		}()

		// Wait for stop or timeout
		select {
		case err := <-stopChan:
			if err != nil {
				log.Printf("Error stopping %s: %v", comp.name, err)
			} else {
				log.Printf("Stopped %s", comp.name)
			}
		case <-stopCtx.Done():
			log.Printf("Timeout stopping %s", comp.name)
		}

		stopCancel()
	}

	// Stop dashboard server with timeout
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	if err := dashboardServer.Stop(stopCtx); err != nil {
		log.Printf("Error stopping dashboard server: %v", err)
	}

	log.Printf("Shutdown complete")
}
