package alert

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// AlertEnricher adds additional context and information to alerts
type AlertEnricher struct {
	mu sync.RWMutex

	// Enrichment data sources
	geoIPDB        map[string]GeoIPInfo
	reputationDB   map[string]IPReputation
	assetInventory map[string]AssetInfo
	vulnDB         map[string][]VulnInfo

	// Cache settings
	cacheTimeout time.Duration
	cacheHits    int
	cacheMisses  int
}

// GeoIPInfo contains geographical information about an IP
type GeoIPInfo struct {
	Country     string    `json:"country"`
	City        string    `json:"city"`
	Coordinates []float64 `json:"coordinates"`
	ASN         string    `json:"asn"`
	ISP         string    `json:"isp"`
}

// IPReputation contains threat intelligence about an IP
type IPReputation struct {
	Score      float64   `json:"score"`      // 0-100, higher is worse
	Categories []string  `json:"categories"` // e.g., "malware", "spam", etc.
	LastSeen   time.Time `json:"last_seen"`
	FirstSeen  time.Time `json:"first_seen"`
	References []string  `json:"references"` // Links to threat reports
	Confidence float64   `json:"confidence"` // 0-1
}

// AssetInfo contains information about internal assets
type AssetInfo struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Owner       string            `json:"owner"`
	Environment string            `json:"environment"`
	Tags        map[string]string `json:"tags"`
	Criticality string            `json:"criticality"`
}

// VulnInfo contains vulnerability information
type VulnInfo struct {
	CVE         string    `json:"cve"`
	CVSS        float64   `json:"cvss"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	References  []string  `json:"references"`
}

// NewAlertEnricher creates a new alert enricher
func NewAlertEnricher() *AlertEnricher {
	return &AlertEnricher{
		geoIPDB:        make(map[string]GeoIPInfo),
		reputationDB:   make(map[string]IPReputation),
		assetInventory: make(map[string]AssetInfo),
		vulnDB:         make(map[string][]VulnInfo),
		cacheTimeout:   time.Hour * 24,
	}
}

// EnrichAlert adds additional context to an alert
func (e *AlertEnricher) EnrichAlert(alert *EnrichedAlert) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Initialize enrichment data if not present
	if alert.EnrichmentData == nil {
		alert.EnrichmentData = make(map[string]interface{})
	}

	// Add basic enrichment data
	alert.EnrichmentData["timestamp"] = alert.Timestamp
	alert.EnrichmentData["priority"] = alert.Priority.String()
	alert.EnrichmentData["severity"] = alert.Severity

	// Add basic tags
	alert.Tags = append(alert.Tags,
		fmt.Sprintf("priority:%s", alert.Priority.String()),
		fmt.Sprintf("severity:%d", alert.Severity),
	)

	// Extract IPs from alert
	ips := e.extractIPs(alert)

	// Add IP-related enrichment
	alert.EnrichmentData["involved_ips"] = ips
	for _, ip := range ips {
		alert.Tags = append(alert.Tags, fmt.Sprintf("ip:%s", ip))

		// Add internal/external classification
		if e.isInternalIP(ip) {
			alert.Tags = append(alert.Tags, "network:internal")
		} else {
			alert.Tags = append(alert.Tags, "network:external")
		}

		// Add GeoIP information if available
		if geoInfo, ok := e.geoIPDB[ip]; ok {
			alert.EnrichmentData["geoip_"+ip] = geoInfo
			alert.Tags = append(alert.Tags, fmt.Sprintf("country:%s", geoInfo.Country))
			e.cacheHits++
		} else {
			e.cacheMisses++
		}

		// Add reputation data if available
		if repInfo, ok := e.reputationDB[ip]; ok {
			alert.EnrichmentData["reputation_"+ip] = repInfo
			for _, category := range repInfo.Categories {
				alert.Tags = append(alert.Tags, fmt.Sprintf("threat:%s", category))
			}
			e.cacheHits++
		} else {
			e.cacheMisses++
		}

		// Add asset information for internal IPs
		if e.isInternalIP(ip) {
			if assetInfo, ok := e.assetInventory[ip]; ok {
				alert.EnrichmentData["asset_"+ip] = assetInfo
				e.cacheHits++

				// Add asset-based tags
				alert.Tags = append(alert.Tags,
					fmt.Sprintf("asset:%s", assetInfo.Name),
					fmt.Sprintf("env:%s", assetInfo.Environment),
					fmt.Sprintf("criticality:%s", assetInfo.Criticality),
				)
			} else {
				e.cacheMisses++
			}
		}
	}

	// Add vulnerability information if applicable
	if vulns := e.findRelevantVulnerabilities(alert); len(vulns) > 0 {
		alert.EnrichmentData["vulnerabilities"] = vulns

		// Add vulnerability-based tags
		for _, vuln := range vulns {
			alert.Tags = append(alert.Tags, fmt.Sprintf("cve:%s", vuln.CVE))
		}
	}

	// Add protocol-specific enrichments
	if protocolInfo := e.enrichProtocolInfo(alert); protocolInfo != nil {
		alert.EnrichmentData["protocol_info"] = protocolInfo
		alert.Tags = append(alert.Tags, fmt.Sprintf("protocol:%s", alert.Protocol))
	}

	// Add time-based context
	hour := alert.Timestamp.Hour()
	if hour >= 18 || hour < 6 {
		alert.Tags = append(alert.Tags, "time:after_hours")
	} else {
		alert.Tags = append(alert.Tags, "time:business_hours")
	}
	alert.Tags = append(alert.Tags, fmt.Sprintf("hour:%d", hour))

	// Deduplicate tags
	alert.Tags = e.deduplicateTags(alert.Tags)

	return nil
}

// extractIPs extracts all IP addresses from an alert
func (e *AlertEnricher) extractIPs(alert *EnrichedAlert) []string {
	var ips []string

	// Extract from source
	if ip := net.ParseIP(alert.Source); ip != nil {
		ips = append(ips, alert.Source)
	}

	// Extract from destination
	if ip := net.ParseIP(alert.Destination); ip != nil {
		ips = append(ips, alert.Destination)
	}

	// Extract from context data
	if contextIPs, ok := alert.Context["involved_ips"].([]string); ok {
		ips = append(ips, contextIPs...)
	}

	return e.deduplicateIPs(ips)
}

// isInternalIP checks if an IP is internal
func (e *AlertEnricher) isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// findRelevantVulnerabilities finds vulnerabilities relevant to the alert
func (e *AlertEnricher) findRelevantVulnerabilities(alert *EnrichedAlert) []VulnInfo {
	var relevant []VulnInfo

	// Check asset vulnerabilities
	if assetIP := alert.Source; e.isInternalIP(assetIP) {
		if vulns, ok := e.vulnDB[assetIP]; ok {
			relevant = append(relevant, vulns...)
		}
	}

	return relevant
}

// enrichProtocolInfo adds protocol-specific enrichment data
func (e *AlertEnricher) enrichProtocolInfo(alert *EnrichedAlert) map[string]interface{} {
	info := make(map[string]interface{})

	switch strings.ToUpper(alert.Protocol) {
	case "HTTP":
		info["known_paths"] = []string{"/admin", "/login", "/api"}
		info["risk_paths"] = []string{"/admin", "/config", "/debug"}
	case "DNS":
		info["query_types"] = []string{"A", "AAAA", "MX", "TXT"}
		info["common_subdomains"] = []string{"www", "mail", "remote", "vpn"}
	case "SSH":
		info["common_usernames"] = []string{"root", "admin", "user"}
		info["secure_ports"] = []int{22, 2222}
	}

	return info
}

// deduplicateIPs removes duplicate IP addresses
func (e *AlertEnricher) deduplicateIPs(ips []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}

	return result
}

// deduplicateTags removes duplicate tags
func (e *AlertEnricher) deduplicateTags(tags []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, tag := range tags {
		if !seen[tag] {
			seen[tag] = true
			result = append(result, tag)
		}
	}

	return result
}

// UpdateGeoIPDB updates the GeoIP database
func (e *AlertEnricher) UpdateGeoIPDB(db map[string]GeoIPInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoIPDB = db
}

// UpdateReputationDB updates the IP reputation database
func (e *AlertEnricher) UpdateReputationDB(db map[string]IPReputation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reputationDB = db
}

// UpdateAssetInventory updates the asset inventory
func (e *AlertEnricher) UpdateAssetInventory(inventory map[string]AssetInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.assetInventory = inventory
}

// UpdateVulnDB updates the vulnerability database
func (e *AlertEnricher) UpdateVulnDB(db map[string][]VulnInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vulnDB = db
}

// GetEnrichmentStats returns statistics about enrichment operations
func (e *AlertEnricher) GetEnrichmentStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"cache_hits":    e.cacheHits,
		"cache_misses":  e.cacheMisses,
		"cache_timeout": e.cacheTimeout,
		"geoip_entries": len(e.geoIPDB),
		"rep_entries":   len(e.reputationDB),
		"asset_entries": len(e.assetInventory),
		"vuln_entries":  len(e.vulnDB),
	}
}
