package baseline

import (
	"encoding/gob"
	"sync"
	"time"
)

func init() {
	// Register types for gob encoding
	gob.Register(&TimeWindow{})
	gob.Register(&WindowManager{})
	gob.Register(time.Month(1))
	gob.Register(time.Weekday(0))
}

// TimeWindow represents a fixed time window for statistics
type TimeWindow struct {
	mu sync.RWMutex

	// Window configuration
	Start    time.Time
	Duration time.Duration

	// Statistics
	PacketCount *EWMA
	ByteCount   *EWMA
	Variance    *VarianceTracker

	// Raw data points within window
	DataPoints []DataPoint
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
		Start:       start,
		Duration:    duration,
		PacketCount: NewEWMA(alpha),
		ByteCount:   NewEWMA(alpha),
		Variance:    NewVarianceTracker(),
		DataPoints:  make([]DataPoint, 0),
	}
}

// AddDataPoint adds a new data point to the window
func (w *TimeWindow) AddDataPoint(point DataPoint) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Update EWMA calculations
	w.PacketCount.Update(float64(point.PacketCount))
	w.ByteCount.Update(float64(point.ByteCount))
	w.Variance.Add(float64(point.PacketCount))

	// Add to raw data points
	w.DataPoints = append(w.DataPoints, point)

	// Remove old data points outside the window
	w.pruneOldDataPoints()
}

// pruneOldDataPoints removes data points outside the current window
func (w *TimeWindow) pruneOldDataPoints() {
	windowStart := w.Start.Add(-w.Duration)
	i := 0
	for ; i < len(w.DataPoints); i++ {
		if w.DataPoints[i].Timestamp.After(windowStart) {
			break
		}
	}
	if i > 0 {
		w.DataPoints = w.DataPoints[i:]
	}
}

// GetStats returns the current window statistics
func (w *TimeWindow) GetStats() (packetRate, byteRate float64, variance float64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	packetRate = w.PacketCount.GetValue()
	byteRate = w.ByteCount.GetValue()
	variance = w.Variance.GetVariance()
	return
}

// GetDataPoints returns all data points in the window
func (w *TimeWindow) GetDataPoints() []DataPoint {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Return a copy to prevent external modification
	points := make([]DataPoint, len(w.DataPoints))
	copy(points, w.DataPoints)
	return points
}

// IsAnomaly checks if the current window contains anomalous behavior
func (w *TimeWindow) IsAnomaly(threshold float64) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.DataPoints) < 2 {
		return false
	}

	// Check for anomalies in packet count
	lastPoint := w.DataPoints[len(w.DataPoints)-1]
	return w.Variance.IsAnomaly(float64(lastPoint.PacketCount), threshold)
}

// GetConfidenceBounds returns the confidence bounds for packet and byte rates
func (w *TimeWindow) GetConfidenceBounds(confidence float64) (packetLower, packetUpper, byteLower, byteUpper float64) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	packetLower, packetUpper = w.PacketCount.GetConfidenceBounds(confidence)
	byteLower, byteUpper = w.ByteCount.GetConfidenceBounds(confidence)
	return
}

// Reset resets the window to its initial state
func (w *TimeWindow) Reset(start time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.Start = start
	w.PacketCount.Reset()
	w.ByteCount.Reset()
	w.Variance.Reset()
	w.DataPoints = w.DataPoints[:0]
}

// WindowManager manages multiple time windows for different time scales
type WindowManager struct {
	mu sync.RWMutex

	// Windows for different time scales
	MinuteWindows map[int]*TimeWindow        // 0-59 minutes
	HourWindows   map[int]*TimeWindow        // 0-23 hours
	DayWindows    map[int]*TimeWindow        // 0-6 days of week
	MonthWindows  map[time.Month]*TimeWindow // 1-12 months
}

// NewWindowManager creates a new window manager
func NewWindowManager(alpha float64) *WindowManager {
	wm := &WindowManager{
		MinuteWindows: make(map[int]*TimeWindow),
		HourWindows:   make(map[int]*TimeWindow),
		DayWindows:    make(map[int]*TimeWindow),
		MonthWindows:  make(map[time.Month]*TimeWindow),
	}

	now := time.Now()

	// Initialize minute windows
	for i := 0; i < 60; i++ {
		wm.MinuteWindows[i] = NewTimeWindow(now, time.Minute, alpha)
	}

	// Initialize hour windows
	for i := 0; i < 24; i++ {
		wm.HourWindows[i] = NewTimeWindow(now, time.Hour, alpha)
	}

	// Initialize day windows
	for i := 0; i < 7; i++ {
		wm.DayWindows[i] = NewTimeWindow(now, 24*time.Hour, alpha)
	}

	// Initialize month windows
	for m := time.January; m <= time.December; m++ {
		wm.MonthWindows[m] = NewTimeWindow(now, 30*24*time.Hour, alpha)
	}

	return wm
}

// AddDataPoint adds a data point to all relevant windows
func (wm *WindowManager) AddDataPoint(point DataPoint) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// Add to minute window
	if w, ok := wm.MinuteWindows[point.Timestamp.Minute()]; ok {
		w.AddDataPoint(point)
	}

	// Add to hour window
	if w, ok := wm.HourWindows[point.Timestamp.Hour()]; ok {
		w.AddDataPoint(point)
	}

	// Add to day window
	if w, ok := wm.DayWindows[int(point.Timestamp.Weekday())]; ok {
		w.AddDataPoint(point)
	}

	// Add to month window
	if w, ok := wm.MonthWindows[point.Timestamp.Month()]; ok {
		w.AddDataPoint(point)
	}
}

// GetWindowStats returns statistics for a specific time window
func (wm *WindowManager) GetWindowStats(t time.Time) (minute, hour, day, month *TimeWindow) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	minute = wm.MinuteWindows[t.Minute()]
	hour = wm.HourWindows[t.Hour()]
	day = wm.DayWindows[int(t.Weekday())]
	month = wm.MonthWindows[t.Month()]
	return
}

// Reset resets all windows
func (wm *WindowManager) Reset() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	now := time.Now()
	for _, w := range wm.MinuteWindows {
		w.Reset(now)
	}
	for _, w := range wm.HourWindows {
		w.Reset(now)
	}
	for _, w := range wm.DayWindows {
		w.Reset(now)
	}
	for _, w := range wm.MonthWindows {
		w.Reset(now)
	}
}
