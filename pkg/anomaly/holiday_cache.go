package anomaly

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	cacheFileName  = "holiday_cache.json"
	defaultMode    = 0644
	defaultDirMode = 0755
)

// HolidayCache represents cached holiday calendar data with thread-safe operations
type HolidayCache struct {
	Holidays   map[string]HolidayInfo `json:"holidays"`
	LastUpdate time.Time              `json:"last_update"`
	ExpiresAt  time.Time              `json:"expires_at"`
	mutex      sync.RWMutex           // Protects concurrent access
}

// HolidayInfo represents information about a holiday
type HolidayInfo struct {
	Name           string `json:"name"`
	Date           string `json:"date"`
	Category       string `json:"category"`
	TrafficPattern string `json:"traffic_pattern"`
	DurationDays   int    `json:"duration_days"`
}

// NewHolidayCache creates a new holiday cache
func NewHolidayCache() *HolidayCache {
	c := clockFactory()
	return &HolidayCache{
		Holidays:   make(map[string]HolidayInfo),
		LastUpdate: c.now(),
		ExpiresAt:  c.now().Add(24 * time.Hour),
	}
}

// LoadCache loads holiday data from the cache file
func LoadCache(cacheDir string) (*HolidayCache, error) {
	// Clean and validate the cache directory path
	cacheDir = filepath.Clean(cacheDir)
	if cacheDir == "" {
		return nil, fmt.Errorf("cache directory path cannot be empty")
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, defaultDirMode); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %v", err)
	}

	cacheFile := filepath.Join(cacheDir, cacheFileName)

	// Check if cache file exists
	_, err := os.Stat(cacheFile)
	if os.IsNotExist(err) {
		// Create new cache with default holidays
		cache := NewHolidayCache()
		if err := initializeDefaultHolidays(cache); err != nil {
			return nil, fmt.Errorf("failed to initialize default holidays: %v", err)
		}
		if err := cache.SaveCache(cacheDir); err != nil {
			return nil, fmt.Errorf("failed to save new cache: %v", err)
		}
		return cache, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to check cache file: %v", err)
	}

	// Read existing cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %v", err)
	}

	var cache HolidayCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to parse cache data: %v", err)
	}

	// Initialize mutex (not stored in JSON)
	cache.mutex = sync.RWMutex{}

	// Check if cache has expired
	c := clockFactory()
	if c.now().After(cache.ExpiresAt) {
		cache.ExpiresAt = c.now().Add(24 * time.Hour)
		cache.LastUpdate = c.now()
		if err := cache.SaveCache(cacheDir); err != nil {
			return nil, fmt.Errorf("failed to save refreshed cache: %v", err)
		}
	}

	return &cache, nil
}

// SaveCache saves the holiday cache to disk using safe file write practices
func (c *HolidayCache) SaveCache(cacheDir string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clean and validate the cache directory path
	cacheDir = filepath.Clean(cacheDir)
	if cacheDir == "" {
		return fmt.Errorf("cache directory path cannot be empty")
	}

	// Ensure the directory exists
	if err := os.MkdirAll(cacheDir, defaultDirMode); err != nil {
		return fmt.Errorf("failed to create cache directory: %v", err)
	}

	// Create a temporary file for atomic write
	tempFile := filepath.Join(cacheDir, fmt.Sprintf(".%s.tmp", cacheFileName))
	cacheFile := filepath.Join(cacheDir, cacheFileName)

	// Marshal the cache data
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %v", err)
	}

	// Write to temporary file
	if err := os.WriteFile(tempFile, data, defaultMode); err != nil {
		os.Remove(tempFile) // Clean up on error
		return fmt.Errorf("failed to write temporary cache file: %v", err)
	}

	// Atomically rename temporary file to final cache file
	if err := os.Rename(tempFile, cacheFile); err != nil {
		os.Remove(tempFile) // Clean up on error
		return fmt.Errorf("failed to save cache file: %v", err)
	}

	return nil
}

// Initialize default holidays for a new cache
func initializeDefaultHolidays(cache *HolidayCache) error {
	defaultHolidays := []struct {
		date string
		info HolidayInfo
	}{
		{
			date: "2024-12-25",
			info: HolidayInfo{
				Name:           "Christmas Day",
				Date:           "2024-12-25",
				Category:       "Federal",
				TrafficPattern: string(PatternReduced),
				DurationDays:   1,
			},
		},
		{
			date: "2024-11-29",
			info: HolidayInfo{
				Name:           "Black Friday",
				Date:           "2024-11-29",
				Category:       "Shopping",
				TrafficPattern: string(PatternElevated),
				DurationDays:   1,
			},
		},
		{
			date: "2024-12-31",
			info: HolidayInfo{
				Name:           "New Year's Eve",
				Date:           "2024-12-31",
				Category:       "Federal",
				TrafficPattern: string(PatternAfterHours),
				DurationDays:   1,
			},
		},
	}

	for _, h := range defaultHolidays {
		cache.AddHoliday(h.date, h.info)
	}

	return nil
}

// Thread-safe methods for cache operations

func (c *HolidayCache) IsExpired() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return clockFactory().now().After(c.ExpiresAt)
}

func (c *HolidayCache) GetHoliday(date string) (HolidayInfo, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Check for exact date match
	if info, exists := c.Holidays[date]; exists {
		return info, true
	}

	// Check for multi-day holidays
	targetDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		return HolidayInfo{}, false
	}

	for _, holiday := range c.Holidays {
		holidayDate, err := time.Parse("2006-01-02", holiday.Date)
		if err != nil {
			continue
		}

		if holiday.DurationDays > 1 {
			holidayEnd := holidayDate.AddDate(0, 0, holiday.DurationDays-1)
			if !targetDate.Before(holidayDate) && !targetDate.After(holidayEnd) {
				return holiday, true
			}
		}
	}

	return HolidayInfo{}, false
}

func (c *HolidayCache) AddHoliday(date string, info HolidayInfo) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.Holidays[date] = info
	c.LastUpdate = clockFactory().now()
}

func (c *HolidayCache) RefreshCache(cacheDir string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.ExpiresAt = clockFactory().now().Add(24 * time.Hour)
	c.LastUpdate = clockFactory().now()

	return c.SaveCache(cacheDir)
}

func (c *HolidayCache) GetHolidaysInRange(start, end time.Time) []HolidayInfo {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var holidays []HolidayInfo
	for _, holiday := range c.Holidays {
		holidayDate, err := time.Parse("2006-01-02", holiday.Date)
		if err != nil {
			continue
		}

		// Check if holiday falls within range
		holidayEnd := holidayDate
		if holiday.DurationDays > 1 {
			holidayEnd = holidayDate.AddDate(0, 0, holiday.DurationDays-1)
		}

		if !holidayDate.After(end) && !holidayEnd.Before(start) {
			holidays = append(holidays, holiday)
		}
	}

	return holidays
}
