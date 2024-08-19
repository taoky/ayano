package parser

import (
	"errors"
	"time"
)

type LogItem struct {
	Size   uint64
	Client string
	Time   time.Time
	URL    string
	Server string
}

var ErrExpectedIgnoredLog = errors.New("ignored")

type Parser interface {
	Parse(line []byte) (LogItem, error)
}
