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
	gob.Register(&CircularBuffer{})
	gob.Register([]DataPoint{})
	gob.Register(DataPoint{})
}

// CircularBuffer represents a fixed-size circular buffer for DataPoints
type CircularBuffer struct {
	Buffer   []DataPoint
	Head     int  // Points to the next write position
	Tail     int  // Points to the oldest element
	Size     int  // Current number of elements
	Capacity int  // Maximum number of elements
	IsFull   bool // Indicates if buffer is full
}

// NewCircularBuffer creates a new circular buffer with given capacity
func NewCircularBuffer(capacity int) *CircularBuffer {
	// Ensure minimum capacity
	if capacity <= 0 {
		capacity = 100 // Default minimum capacity
	}

	return &CircularBuffer{
		Buffer:   make([]DataPoint, capacity),
		Capacity: capacity,
		Head:     0,
		Tail:     0,
		Size:     0,
		IsFull:   false,
	}
}

// Add adds a data point to the circular buffer
func (cb *CircularBuffer) Add(point DataPoint) {
	cb.Buffer[cb.Head] = point
	cb.Head = (cb.Head + 1) % cb.Capacity

	if cb.IsFull {
		cb.Tail = (cb.Tail + 1) % cb.Capacity
	} else {
		cb.Size++
		if cb.Size == cb.Capacity {
			cb.IsFull = true
		}
	}
}

// GetPoints returns all valid points within the time window
func (cb *CircularBuffer) GetPoints(since time.Time) []DataPoint {
	if cb.Size == 0 {
		return nil
	}

	points := make([]DataPoint, 0, cb.Size)
	idx := cb.Tail
	count := 0

	for count < cb.Size {
		if cb.Buffer[idx].Timestamp.After(since) {
			points = append(points, cb.Buffer[idx])
		}
		idx = (idx + 1) % cb.Capacity
		count++
	}

	return points
}

// DataPointPool is a sync.Pool for DataPoint objects
var DataPointPool = sync.Pool{
	New: func() interface{} {
		return &DataPoint{}
	},
}

// DataPoint represents a single measurement in time
type DataPoint struct {
	Timestamp   time.Time
	PacketCount uint64
	ByteCount   uint64
}

// Reset resets the DataPoint to zero values
func (dp *DataPoint) Reset() {
	dp.Timestamp = time.Time{}
	dp.PacketCount = 0
	dp.ByteCount = 0
}

// Put puts a DataPoint back into the pool after resetting it
func (dp *DataPoint) Put() {
	dp.Reset()
	DataPointPool.Put(dp)
}

// GetDataPoint gets a DataPoint from the pool
func GetDataPoint() *DataPoint {
	return DataPointPool.Get().(*DataPoint)
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

	// Circular buffer for time series data
	buffer *CircularBuffer
}

// NewTimeWindow creates a new time window
func NewTimeWindow(start time.Time, duration time.Duration, alpha float64) *TimeWindow {
	// Calculate buffer size based on duration and expected data rate
	// Assuming 1 data point per second as a baseline
	bufferSize := int(duration.Seconds()) * 2 // Double the size for safety
	if bufferSize < 100 {
		bufferSize = 100 // Minimum buffer size
	}

	return &TimeWindow{
		Start:       start,
		Duration:    duration,
		PacketCount: NewEWMA(alpha),
		ByteCount:   NewEWMA(alpha),
		Variance:    NewVarianceTracker(),
		buffer:      NewCircularBuffer(bufferSize),
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

	// Add to circular buffer
	w.buffer.Add(point)
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

	windowStart := w.Start.Add(-w.Duration)
	return w.buffer.GetPoints(windowStart)
}

// Reset resets the window to its initial state
func (w *TimeWindow) Reset(start time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.Start = start
	w.PacketCount.Reset()
	w.ByteCount.Reset()
	w.Variance.Reset()
	w.buffer = NewCircularBuffer(w.buffer.Capacity)
}

// IsAnomaly checks if the current window contains anomalous behavior
func (w *TimeWindow) IsAnomaly(threshold float64) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	points := w.buffer.GetPoints(w.Start.Add(-w.Duration))
	if len(points) < 2 {
		return false
	}

	lastPoint := points[len(points)-1]
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
