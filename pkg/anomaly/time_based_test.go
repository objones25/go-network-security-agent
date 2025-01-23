package anomaly

import (
	"testing"
	"time"

	"github.com/objones25/go-network-security-agent/pkg/capture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClock provides a controllable clock implementation for testing
type mockClock struct {
	current time.Time
}

func newMockClock(t time.Time) *mockClock {
	return &mockClock{current: t}
}

func (m *mockClock) now() time.Time {
	return m.current
}

func (m *mockClock) since(t time.Time) time.Duration {
	return m.current.Sub(t)
}

func (m *mockClock) until(t time.Time) time.Duration {
	return t.Sub(m.current)
}

func TestEvaluateWeekendTraffic(t *testing.T) {
	// Create a temporary directory for cache
	tmpDir := t.TempDir()

	rule, err := NewTimeBasedAnomalyRule(
		"time_test",
		9,                  // startHour
		17,                 // endHour
		2.0,                // weekendMultiplier
		"America/New_York", // timezone
		tmpDir,             // cacheDir
	)
	require.NoError(t, err)

	// Create test context with known activity patterns
	ctx := &DetectionContext{
		CurrentSnapshot: capture.StatsSnapshot{
			ActiveConnections: map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80": 90, // 1.5x normal traffic
			},
		},
		Metadata: map[string]interface{}{
			"activity_patterns": map[string]float64{
				"09": 50.0, // Normal business hours baseline
				"14": 60.0, // Peak business hours
				"16": 50.0, // Normal business hours baseline
			},
		},
	}

	// Test cases for weekend traffic
	tests := []struct {
		name     string
		time     time.Time
		traffic  uint64
		expected bool
	}{
		{
			name:     "Normal Weekend Traffic",
			time:     time.Date(2024, 3, 16, 14, 0, 0, 0, time.UTC), // Saturday
			traffic:  90,                                            // 1.5x normal (below 2.0x threshold)
			expected: false,
		},
		{
			name:     "Excessive Weekend Traffic",
			time:     time.Date(2024, 3, 17, 14, 0, 0, 0, time.UTC), // Sunday
			traffic:  150,                                           // 2.5x normal (above 2.0x threshold)
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock clock
			mock := newMockClock(tt.time)

			// Update test context with traffic
			ctx.CurrentSnapshot.ActiveConnections = map[string]uint64{
				"192.168.1.100:12345->10.0.0.1:80": tt.traffic,
			}

			// Call the method directly with our mock clock
			result := rule.evaluateWeekendTraffic(ctx, mock)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateHolidayTraffic(t *testing.T) {
	// Create a temporary directory for cache
	tmpDir := t.TempDir()

	rule, err := NewTimeBasedAnomalyRule(
		"holiday_test",
		9,                  // startHour
		17,                 // endHour
		2.0,                // weekendMultiplier
		"America/New_York", // timezone
		tmpDir,             // cacheDir
	)
	require.NoError(t, err)

	// Test cases for holiday traffic
	tests := []struct {
		name     string
		date     string
		info     HolidayInfo
		traffic  uint64
		expected bool
	}{
		{
			name: "Reduced Traffic Holiday - Normal",
			date: "2024-12-25",
			info: HolidayInfo{
				Name:           "Christmas Day",
				Date:           "2024-12-25",
				Category:       "federal",
				TrafficPattern: string(PatternReduced),
				DurationDays:   1,
			},
			traffic:  40, // Below reduced threshold
			expected: false,
		},
		{
			name: "Elevated Traffic Holiday - High",
			date: "2024-11-29",
			info: HolidayInfo{
				Name:           "Black Friday",
				Date:           "2024-11-29",
				Category:       "shopping",
				TrafficPattern: string(PatternElevated),
				DurationDays:   1,
			},
			traffic:  150, // Above elevated threshold
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the holiday date
			testDate, err := time.Parse("2006-01-02", tt.date)
			require.NoError(t, err)

			// Set up mock clock at 2 PM on the holiday
			mock := newMockClock(
				time.Date(testDate.Year(), testDate.Month(), testDate.Day(), 14, 0, 0, 0, time.UTC),
			)

			// Create test context
			ctx := &DetectionContext{
				CurrentSnapshot: capture.StatsSnapshot{
					ActiveConnections: map[string]uint64{
						"192.168.1.100:12345->10.0.0.1:80": tt.traffic,
					},
				},
				Metadata: map[string]interface{}{
					"activity_patterns": map[string]float64{
						"09": 50.0, // Normal business hours baseline
						"14": 60.0, // Peak business hours
						"16": 50.0, // Normal business hours baseline
					},
				},
			}

			// Call the method directly with our mock clock
			result := rule.evaluateHolidayTraffic(ctx, tt.info, mock)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateBusinessDayTraffic(t *testing.T) {
	// Create a temporary directory for cache
	tmpDir := t.TempDir()

	rule, err := NewTimeBasedAnomalyRule(
		"business_test",
		9,                  // startHour
		17,                 // endHour
		2.0,                // weekendMultiplier
		"America/New_York", // timezone
		tmpDir,             // cacheDir
	)
	require.NoError(t, err)

	// Test cases for business day traffic
	tests := []struct {
		name     string
		time     time.Time
		traffic  uint64
		expected bool
	}{
		{
			name:     "Normal Business Hours",
			time:     time.Date(2024, 3, 13, 14, 0, 0, 0, time.UTC), // Wednesday 2 PM
			traffic:  70,                                            // Slightly above normal
			expected: false,
		},
		{
			name:     "High Business Hours",
			time:     time.Date(2024, 3, 13, 14, 0, 0, 0, time.UTC), // Wednesday 2 PM
			traffic:  150,                                           // Well above normal
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock clock
			mock := newMockClock(tt.time)

			// Create test context
			ctx := &DetectionContext{
				CurrentSnapshot: capture.StatsSnapshot{
					ActiveConnections: map[string]uint64{
						"192.168.1.100:12345->10.0.0.1:80": tt.traffic,
					},
				},
				Metadata: map[string]interface{}{
					"activity_patterns": map[string]float64{
						"09": 50.0, // Normal business hours baseline
						"14": 60.0, // Peak business hours
						"16": 50.0, // Normal business hours baseline
					},
				},
			}

			// Call the method directly with our mock clock
			result := rule.evaluateBusinessDayTraffic(ctx, tt.time.Hour(), mock)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateAfterHoursTraffic(t *testing.T) {
	// Create a temporary directory for cache
	tmpDir := t.TempDir()

	rule, err := NewTimeBasedAnomalyRule(
		"after_hours_test",
		9,                  // startHour
		17,                 // endHour
		2.0,                // weekendMultiplier
		"America/New_York", // timezone
		tmpDir,             // cacheDir
	)
	require.NoError(t, err)

	// Test cases for after-hours traffic
	tests := []struct {
		name     string
		time     time.Time
		traffic  uint64
		expected bool
	}{
		{
			name:     "Normal After Hours",
			time:     time.Date(2024, 3, 13, 22, 0, 0, 0, time.UTC), // Wednesday 10 PM
			traffic:  40,                                            // Below threshold
			expected: false,
		},
		{
			name:     "High After Hours",
			time:     time.Date(2024, 3, 13, 22, 0, 0, 0, time.UTC), // Wednesday 10 PM
			traffic:  200,                                           // Above threshold
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock clock
			mock := newMockClock(tt.time)

			// Create test context
			ctx := &DetectionContext{
				CurrentSnapshot: capture.StatsSnapshot{
					ActiveConnections: map[string]uint64{
						"192.168.1.100:12345->10.0.0.1:80": tt.traffic,
					},
				},
				Metadata: map[string]interface{}{
					"activity_patterns": map[string]float64{
						"09": 50.0, // Normal business hours baseline
						"14": 60.0, // Peak business hours
						"16": 50.0, // Normal business hours baseline
					},
				},
			}

			// Call the method directly with our mock clock
			result := rule.evaluateAfterHoursTraffic(ctx, mock)
			assert.Equal(t, tt.expected, result)
		})
	}
}
