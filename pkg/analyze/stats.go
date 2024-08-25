package analyze

import "time"

const DateFormat = "2006-01-02 15:04:05"

type IPStats struct {
	Size      uint64
	Requests  uint64
	LastURL   string
	LastSize  uint64
	FirstSeen time.Time

	// Record time of last URL change
	LastURLUpdate time.Time

	// Record time of last URL access
	LastURLAccess time.Time
}
