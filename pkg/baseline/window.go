package baseline

import (
	"sync"
	"time"
)

// TimeWindow represents a fixed time window for statistics
type TimeWindow struct {
	mu sync.RWMutex

	// Window configuration
	start    time.Time
	duration time.Duration

	// Statistics
	packetCount *EWMA
	byteCount   *EWMA
	variance    *VarianceTracker

	// Raw data points within window
	dataPoints []DataPoint
}

// DataPoint represents a single measurement in time
type DataPoint struct {
	Timestamp   time.Time
	PacketCount uint64
	ByteCount   uint64
}

// NewTimeWindow creates a new time window
func NewTimeWindow(start time.Time, duration time.Duration, alpha float64) *TimeWindow {
	return &TimeWindow{
		start:       start,
		duration:    duration,
		packetCount: NewEWMA(alpha),
		byteCount:   NewEWMA(alpha),
		variance:    NewVarianceTracker(),
		dataPoints:  make([]DataPoint, 0),
	}
}

// AddDataPoint adds a new data point to the window
func (w *TimeWindow) AddDataPoint(point DataPoint) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Update EWMA calculations
	w.packetCount.Update(float64(point.PacketCount))
	w.byteCount.Update(float64(point.ByteCount))
	w.variance.Add(float64(point.PacketCount))

	// Add to raw data points
	w.dataPoints = append(w.dataPoints, point)

	// Remove old data points outside the window
	w.pruneOldDataPoints()
}

// pruneOldDataPoints removes data points outside the current window
func (w *TimeWindow) pruneOldDataPoints() {
	windowStart := w.start.Add(-w.duration)
	i := 0
	for ; i < len(w.dataPoints); i++ {
		if w.dataPoints[i].Timestamp.After(windowStart) {
			break
		}
	}
	if i > 0 {
		w.dataPoints = w.dataPoints[i:]
	}
}

// GetStats returns the current window statistics
func (w *TimeWindow) GetStats() (packetRate, byteRate float64, variance float64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	packetRate = w.packetCount.GetValue()
	byteRate = w.byteCount.GetValue()
	variance = w.variance.GetVariance()
	return
}

// GetDataPoints returns all data points in the window
func (w *TimeWindow) GetDataPoints() []DataPoint {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Return a copy to prevent external modification
	points := make([]DataPoint, len(w.dataPoints))
	copy(points, w.dataPoints)
	return points
}

// IsAnomaly checks if the current window contains anomalous behavior
func (w *TimeWindow) IsAnomaly(threshold float64) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.dataPoints) < 2 {
		return false
	}

	// Check for anomalies in packet count
	lastPoint := w.dataPoints[len(w.dataPoints)-1]
	return w.variance.IsAnomaly(float64(lastPoint.PacketCount), threshold)
}

// GetConfidenceBounds returns the confidence bounds for packet and byte rates
func (w *TimeWindow) GetConfidenceBounds(confidence float64) (packetLower, packetUpper, byteLower, byteUpper float64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	packetLower, packetUpper = w.packetCount.GetConfidenceBounds(confidence)
	byteLower, byteUpper = w.byteCount.GetConfidenceBounds(confidence)
	return
}

// Reset resets the window to its initial state
func (w *TimeWindow) Reset(start time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.start = start
	w.packetCount.Reset()
	w.byteCount.Reset()
	w.variance.Reset()
	w.dataPoints = w.dataPoints[:0]
}

// WindowManager manages multiple time windows for different time scales
type WindowManager struct {
	mu sync.RWMutex

	// Windows for different time scales
	minuteWindows map[int]*TimeWindow        // 0-59 minutes
	hourWindows   map[int]*TimeWindow        // 0-23 hours
	dayWindows    map[int]*TimeWindow        // 0-6 days of week
	monthWindows  map[time.Month]*TimeWindow // 1-12 months
}

// NewWindowManager creates a new window manager
func NewWindowManager(alpha float64) *WindowManager {
	wm := &WindowManager{
		minuteWindows: make(map[int]*TimeWindow),
		hourWindows:   make(map[int]*TimeWindow),
		dayWindows:    make(map[int]*TimeWindow),
		monthWindows:  make(map[time.Month]*TimeWindow),
	}

	now := time.Now()

	// Initialize minute windows
	for i := 0; i < 60; i++ {
		wm.minuteWindows[i] = NewTimeWindow(now, time.Minute, alpha)
	}

	// Initialize hour windows
	for i := 0; i < 24; i++ {
		wm.hourWindows[i] = NewTimeWindow(now, time.Hour, alpha)
	}

	// Initialize day windows
	for i := 0; i < 7; i++ {
		wm.dayWindows[i] = NewTimeWindow(now, 24*time.Hour, alpha)
	}

	// Initialize month windows
	for m := time.January; m <= time.December; m++ {
		wm.monthWindows[m] = NewTimeWindow(now, 30*24*time.Hour, alpha)
	}

	return wm
}

// AddDataPoint adds a data point to all relevant windows
func (wm *WindowManager) AddDataPoint(point DataPoint) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// Add to minute window
	if w, ok := wm.minuteWindows[point.Timestamp.Minute()]; ok {
		w.AddDataPoint(point)
	}

	// Add to hour window
	if w, ok := wm.hourWindows[point.Timestamp.Hour()]; ok {
		w.AddDataPoint(point)
	}

	// Add to day window
	if w, ok := wm.dayWindows[int(point.Timestamp.Weekday())]; ok {
		w.AddDataPoint(point)
	}

	// Add to month window
	if w, ok := wm.monthWindows[point.Timestamp.Month()]; ok {
		w.AddDataPoint(point)
	}
}

// GetWindowStats returns statistics for a specific time window
func (wm *WindowManager) GetWindowStats(t time.Time) (minute, hour, day, month *TimeWindow) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	minute = wm.minuteWindows[t.Minute()]
	hour = wm.hourWindows[t.Hour()]
	day = wm.dayWindows[int(t.Weekday())]
	month = wm.monthWindows[t.Month()]
	return
}

// Reset resets all windows
func (wm *WindowManager) Reset() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	now := time.Now()
	for _, w := range wm.minuteWindows {
		w.Reset(now)
	}
	for _, w := range wm.hourWindows {
		w.Reset(now)
	}
	for _, w := range wm.dayWindows {
		w.Reset(now)
	}
	for _, w := range wm.monthWindows {
		w.Reset(now)
	}
}
