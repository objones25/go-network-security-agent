package alert

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// AlertCorrelator handles alert correlation and relationship detection
type AlertCorrelator struct {
	mu sync.RWMutex

	// Correlation settings
	timeWindow       time.Duration
	minSimilarity    float64
	maxRelatedAlerts int

	// Correlation metrics
	correlationCount int
	lastCorrelation  time.Time
}

// NewAlertCorrelator creates a new alert correlator
func NewAlertCorrelator() *AlertCorrelator {
	return &AlertCorrelator{
		timeWindow:       time.Hour,
		minSimilarity:    0.7,
		maxRelatedAlerts: 10,
	}
}

// CorrelateAlert correlates a new alert with existing alerts
func (c *AlertCorrelator) CorrelateAlert(alert *EnrichedAlert) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Add basic correlation tags
	alert.Tags = append(alert.Tags,
		fmt.Sprintf("source:%s", alert.Source),
		fmt.Sprintf("protocol:%s", alert.Protocol),
		fmt.Sprintf("severity:%s", alert.Priority.String()),
	)

	// Add metric-based tag
	if alert.MetricName != "" {
		alert.Tags = append(alert.Tags, fmt.Sprintf("metric:%s", alert.MetricName))
	}

	c.correlationCount++
	c.lastCorrelation = time.Now()

	return nil
}

// CorrelateAlerts performs correlation analysis on a set of alerts
func (c *AlertCorrelator) CorrelateAlerts(alerts map[string]*EnrichedAlert, window time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Group alerts by time windows
	timeGroups := make(map[time.Time][]*EnrichedAlert)
	for _, alert := range alerts {
		windowStart := alert.Timestamp.Truncate(window)
		timeGroups[windowStart] = append(timeGroups[windowStart], alert)
	}

	// Analyze each time window
	for _, group := range timeGroups {
		if err := c.analyzeAlertGroup(group); err != nil {
			return fmt.Errorf("failed to analyze alert group: %v", err)
		}
	}

	return nil
}

// analyzeAlertGroup performs correlation analysis on a group of alerts
func (c *AlertCorrelator) analyzeAlertGroup(alerts []*EnrichedAlert) error {
	if len(alerts) < 2 {
		return nil
	}

	// Build similarity matrix
	similarities := make([][]float64, len(alerts))
	for i := range similarities {
		similarities[i] = make([]float64, len(alerts))
	}

	// Calculate pairwise similarities
	for i := 0; i < len(alerts); i++ {
		for j := i + 1; j < len(alerts); j++ {
			sim := c.calculateSimilarity(alerts[i], alerts[j])
			similarities[i][j] = sim
			similarities[j][i] = sim

			// If similarity exceeds threshold, mark as related
			if sim >= c.minSimilarity {
				c.markAlertsAsRelated(alerts[i], alerts[j])
			}
		}
	}

	return nil
}

// calculateSimilarity computes the similarity between two alerts
func (c *AlertCorrelator) calculateSimilarity(a1, a2 *EnrichedAlert) float64 {
	var similarities []float64

	// Time proximity (closer in time = more similar)
	timeProximity := 1.0 - math.Min(1.0, a1.Timestamp.Sub(a2.Timestamp).Hours()/24.0)
	similarities = append(similarities, timeProximity)

	// Metric similarity
	if a1.MetricName == a2.MetricName {
		similarities = append(similarities, 1.0)
	} else {
		similarities = append(similarities, 0.0)
	}

	// Source similarity
	if a1.Source == a2.Source {
		similarities = append(similarities, 1.0)
	} else {
		similarities = append(similarities, 0.0)
	}

	// Protocol similarity
	if a1.Protocol == a2.Protocol {
		similarities = append(similarities, 1.0)
	} else {
		similarities = append(similarities, 0.0)
	}

	// Tag similarity
	tagSim := c.calculateTagSimilarity(a1.Tags, a2.Tags)
	similarities = append(similarities, tagSim)

	// Calculate weighted average
	weights := []float64{0.3, 0.2, 0.2, 0.15, 0.15} // Must sum to 1.0
	weightedSum := 0.0
	for i, sim := range similarities {
		weightedSum += sim * weights[i]
	}

	return weightedSum
}

// calculateTagSimilarity computes Jaccard similarity between tag sets
func (c *AlertCorrelator) calculateTagSimilarity(tags1, tags2 []string) float64 {
	if len(tags1) == 0 && len(tags2) == 0 {
		return 1.0
	}
	if len(tags1) == 0 || len(tags2) == 0 {
		return 0.0
	}

	// Convert to maps for O(1) lookup
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)
	for _, tag := range tags1 {
		set1[tag] = true
	}
	for _, tag := range tags2 {
		set2[tag] = true
	}

	// Calculate intersection and union sizes
	intersection := 0
	for tag := range set1 {
		if set2[tag] {
			intersection++
		}
	}
	union := len(set1) + len(set2) - intersection

	return float64(intersection) / float64(union)
}

// markAlertsAsRelated establishes a relationship between two alerts
func (c *AlertCorrelator) markAlertsAsRelated(a1, a2 *EnrichedAlert) {
	// Check if we've reached the maximum related alerts for either alert
	if len(a1.RelatedAlerts) >= c.maxRelatedAlerts || len(a2.RelatedAlerts) >= c.maxRelatedAlerts {
		return
	}

	// Add bidirectional relationship
	a1.RelatedAlerts = append(a1.RelatedAlerts, a2.ID)
	a2.RelatedAlerts = append(a2.RelatedAlerts, a1.ID)
}

// GetCorrelationStats returns statistics about correlation operations
func (c *AlertCorrelator) GetCorrelationStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"correlation_count": c.correlationCount,
		"last_correlation":  c.lastCorrelation,
		"time_window":       c.timeWindow,
		"min_similarity":    c.minSimilarity,
	}
}
