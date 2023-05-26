package parser

import "time"

type LogItem struct {
	Size   uint64
	Client string
	Time   time.Time
	URL    string
	Server string
}

type Parser interface {
	Parse(line string) (LogItem, error)
}
