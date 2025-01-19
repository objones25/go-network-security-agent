# Network Security Agent

A sophisticated network monitoring tool written in Go that uses machine learning and statistical analysis to detect network anomalies and potential security threats. Designed for personal/home network monitoring with a focus on learning about network security patterns.

## Core Features

### Multi-Level Anomaly Detection
- **CRITICAL Alerts** (Immediate Notification)
  - Port scan detection
  - Known malware signature matches
  - Unauthorized privileged port access
  - Connections from known malicious IPs

- **WARNING Level** (Dashboard Alerts)
  - Unusual traffic volumes
  - New destination IPs/ports
  - Statistical deviations from baseline
  - Suspicious DNS query patterns

- **INFO Level** (Dashboard Trends)
  - General traffic patterns
  - Baseline learning progress
  - Network usage statistics

### Intelligent Baseline Learning

#### Initial Statistical Analysis
1. **Moving Average Baseline**
   - Exponentially Weighted Moving Average (EWMA) for traffic volumes
   - Separate averages for different protocols (TCP, UDP, ICMP)
   - Time-window based calculations (hourly, daily, weekly patterns)
   - Adaptive thresholds based on time of day

2. **Variance-Based Anomaly Detection**
   - Rolling variance calculations
   - Z-score computation for deviation detection
   - Protocol-specific threshold adjustments
   - Seasonal variance consideration (work hours vs. off hours)

3. **Connection Pattern Analysis**
   - Connection frequency baselines
   - Duration patterns for persistent connections
   - Port usage distribution
   - Destination IP clustering

4. **Traffic Volume Profiling**
   - Byte count distribution analysis
   - Protocol-specific volume patterns
   - Burst pattern detection
   - Bandwidth utilization profiling

#### Future ML Enhancements
1. **Time Series Analysis**
   - ARIMA/SARIMA for seasonal pattern detection
   - Prophet for trend decomposition
   - LSTM for sequence prediction
   - Anomaly detection using forecasting

2. **Clustering Techniques**
   - K-means for initial traffic pattern clustering
   - DBSCAN for density-based pattern detection
   - Hierarchical clustering for protocol behavior
   - Gaussian Mixture Models for distribution learning

3. **Advanced Pattern Recognition**
   - Random Forest for multi-feature analysis
   - Isolation Forest for anomaly detection
   - One-class SVM for novelty detection
   - Autoencoder-based anomaly detection

### Compliance Framework Integration

#### NIST Cybersecurity Framework Implementation
1. **Identify**
   - Automated asset discovery and categorization
   - Network topology mapping
   - Risk scoring based on traffic patterns
   - Data flow documentation
   - System dependency mapping

2. **Protect**
   - Port access control monitoring
   - Encryption usage tracking
   - Authentication attempt monitoring
   - Security policy enforcement checking
   - Configuration change detection

3. **Detect**
   - Real-time anomaly detection
   - Behavioral baseline monitoring
   - Threat pattern recognition
   - Incident alerting system
   - Continuous monitoring implementation

4. **Respond**
   - Automated alert generation
   - Incident classification
   - Response procedure tracking
   - Communication workflow automation
   - Impact assessment tools

5. **Recover**
   - Recovery time tracking
   - System restoration monitoring
   - Post-incident analysis tools
   - Improvement tracking
   - Backup verification

#### GDPR Compliance Monitoring
1. **Data Privacy**
   - Personal data flow tracking
   - Cross-border transfer detection
   - Data access pattern monitoring
   - Privacy policy compliance checking

2. **Data Protection**
   - Encryption monitoring
   - Access control verification
   - Data retention compliance
   - Processing purpose validation

3. **Rights Management**
   - Subject access request tracking
   - Data modification monitoring
   - Deletion verification
   - Processing restriction tracking

#### ISO 27001 Controls
1. **Information Security**
   - Access control monitoring
   - Cryptography usage tracking
   - Security event logging
   - Asset management tracking

2. **Risk Management**
   - Threat detection and logging
   - Vulnerability monitoring
   - Risk assessment automation
   - Control effectiveness tracking

3. **Performance Measurement**
   - Security metrics collection
   - Control effectiveness monitoring
   - Compliance status tracking
   - Improvement measurement

### Dashboard & Visualization

#### Core Metrics & Visualizations

1. **Network Traffic Overview**
   - Real-time traffic volume line chart with protocol breakdown
   - Connection count sparklines with historical trends
   - Interactive network topology graph showing active connections
   - Geographic traffic distribution world map with heat regions
   - Protocol distribution donut chart with drill-down capability

2. **Security Visualization**
   - Multi-level alert timeline with severity color coding
   - Port scan attempt heatmap (ports vs. time)
   - Connection attempt force-directed graph
   - DNS query pattern tree map
   - Anomaly score gauge charts with historical context
   - Traffic pattern deviation charts with baseline comparison

3. **Performance Analytics**
   - Bandwidth utilization stacked area charts
   - Latency distribution violin plots
   - Packet loss waterfall charts
   - Response time heat calendar
   - Resource usage radar charts
   - Connection quality metrics bubble chart

4. **Historical Analysis Tools**
   - Interactive time-series analysis with zoom capabilities
   - Pattern comparison parallel coordinates plot
   - Baseline adaptation river plot
   - Learning progress metrics dashboard
   - Anomaly correlation matrix
   - Traffic pattern clustering visualization

#### Interactive Features
1. **Real-time Monitoring**
   ```
   ┌─ Network Activity ──────┐  ┌─ Active Alerts ────┐
   │     ↗                   │  │ • Critical: 2      │
   │   ↗                     │  │ • Warning: 5       │
   │ ↗        Traffic Volume │  │ • Info: 12         │
   └─────────────────────────┘  └──────────────────┘
   
   ┌─ Connection Map ────────────────────────────────┐
   │              ●──────●              ●────●       │
   │          ●───●     │          ●───●    │       │
   │          │         │          │        │       │
   │          ●         ●          ●        ●       │
   └──────────────────────────────────────────────┘
   ```

2. **Analysis Workbench**
   - Drag-and-drop query builder
   - Custom visualization creator
   - Pattern matching interface
   - Rule configuration builder

3. **Configuration Dashboard**
   - Visual threshold adjustment sliders
   - Baseline management interface
   - Alert rule configuration matrix
   - Machine learning parameter tuning dashboard

## Technical Architecture

### Core Components
1. **Packet Capture Engine**
   - Raw packet capture using libpcap
   - Packet parsing and classification
   - Protocol analysis

2. **Baseline Manager**
   - Initial: Simple statistical modeling
   - Future: Machine learning integration
   - Pattern storage
   - Adaptive thresholds

3. **Anomaly Detector**
   - Multi-level detection system
   - Pattern matching
   - Threat classification

4. **Alert Manager**
   - Alert prioritization
   - Notification dispatch
   - Alert history

5. **Dashboard Server**
   - Data aggregation
   - Real-time updates
   - Visualization generation

## Development Roadmap

### Phase 1: Foundation (Current)
- Basic packet capture and analysis
- Simple statistical baseline
- Critical alert implementation
- Command-line interface
- Basic dashboard with core metrics

### Phase 2: Intelligence Enhancement
- Basic machine learning integration
- Improved baseline adaptation
- Enhanced visualization
- Initial compliance framework implementation

### Phase 3: Advanced Features
- Advanced ML algorithms
- Compliance framework expansion
- Custom rule creation
- Comprehensive dashboard

### Phase 4: Optimization
- Performance tuning
- False positive reduction
- ML model optimization
- Dashboard enhancement

## Contributing

We welcome contributions! Here's how you can help:

### Getting Started
1. Fork the repository
2. Create a feature branch
3. Write clear, documented code
4. Submit a pull request

### Areas for Contribution
- Core agent functionality
- Machine learning algorithms
- Dashboard features
- Documentation
- Testing and validation

### Best Practices
- Follow Go best practices and idioms
- Write tests for new features
- Document your code
- Keep performance in mind
- Start simple, refactor as needed

### Code Review Process
1. Code review by maintainers
2. Testing requirements
3. Documentation review
4. Performance review if applicable

## License

MIT License - See LICENSE file for details

## Setup and Configuration

### Prerequisites
- Go 1.21 or higher
- libpcap development files
- Node.js 18+ (for dashboard)
- Docker (optional, for containerized deployment)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/network-security-agent
   cd network-security-agent
   ```

2. **Install Dependencies**
   ```bash
   # Install Go dependencies
   go mod download

   # Install dashboard dependencies
   cd dashboard
   npm install
   ```

3. **Initial Configuration**
   ```bash
   # Generate default configuration
   go run cmd/config/generate.go

   # Edit configuration file
   vim config/agent.yaml
   ```

### Basic Configuration (agent.yaml)
```yaml
agent:
  name: "home-network-monitor"
  interface: "eth0"  # Network interface to monitor
  log_level: "info"

capture:
  promiscuous: true
  snapshot_len: 65535
  timeout: "1s"

baseline:
  initial_learning_period: "24h"
  update_interval: "1h"
  min_samples: 1000

alerts:
  critical:
    notification: true
    desktop: true
    log: true
  warning:
    notification: true
    desktop: false
    log: true
  info:
    notification: false
    desktop: false
    log: true

dashboard:
  port: 3000
  metrics_retention: "30d"
  update_interval: "1s"
```

### Running the Agent

1. **Start in Basic Mode**
   ```bash
   sudo go run cmd/agent/main.go
   ```

2. **Start with Custom Configuration**
   ```bash
   sudo go run cmd/agent/main.go --config path/to/config.yaml
   ```

3. **Start Dashboard**
   ```bash
   cd dashboard
   npm run dev
   ```

### Initial Setup Steps

1. **Network Interface Selection**
   - List available interfaces:
     ```bash
     go run cmd/tools/list-interfaces.go
     ```
   - Update configuration with chosen interface

2. **Baseline Learning**
   - Initial learning period (24 hours recommended)
   - Basic statistical baseline establishment
   - Initial threshold calibration

3. **Alert Configuration**
   - Set notification preferences
   - Configure alert thresholds
   - Set up external notification services (optional)

4. **Dashboard Setup**
   - Configure authentication (if needed)
   - Set up SSL/TLS (recommended)
   - Configure data retention policies

### Advanced Configuration

1. **Custom Detection Rules**
   ```yaml
   rules:
     - name: "high-volume-connection"
       condition: "bytes_per_second > 1000000"
       level: "WARNING"
     
     - name: "repeated-auth-failure"
       condition: "auth_failures > 5 && timespan < 300"
       level: "CRITICAL"
   ```

2. **ML Pipeline Configuration**
   ```yaml
   ml_config:
     models:
       - type: "anomaly_detection"
         algorithm: "isolation_forest"
         params:
           contamination: 0.1
           n_estimators: 100
       
       - type: "clustering"
         algorithm: "dbscan"
         params:
           eps: 0.5
           min_samples: 5
   ```

3. **Visualization Settings**
   ```yaml
   visualizations:
     network_graph:
       update_interval: "5s"
       node_limit: 100
       edge_threshold: 0.1
     
     heatmaps:
       color_scheme: "viridis"
       resolution: "1min"
   ```

### Troubleshooting

1. **Common Issues**
   - Permission denied: Run with sudo or configure capabilities
   - Interface not found: Check interface name and permissions
   - Dashboard connection failed: Check port availability

2. **Logging**
   - Location: `/var/log/network-agent/`
   - Log rotation configuration
   - Debug level adjustment

3. **Performance Tuning**
   - Memory allocation settings
   - Packet buffer sizes
   - Database optimization