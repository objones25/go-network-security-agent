package anomaly

import (
	"sync"
	"time"
)

// clock is an internal interface for time operations
type clock interface {
	now() time.Time
	since(t time.Time) time.Duration
	until(t time.Time) time.Duration
}

// clockFactory is a package-private singleton for clock creation
var (
	clockFactoryMu sync.RWMutex
	clockFactory   = func() clock {
		return &realClock{}
	}
)

// realClock uses actual system time
type realClock struct{}

func (r *realClock) now() time.Time {
	return time.Now()
}

func (r *realClock) since(t time.Time) time.Duration {
	return time.Since(t)
}

func (r *realClock) until(t time.Time) time.Duration {
	return time.Until(t)
}
