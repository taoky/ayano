package parser

import (
	"errors"
	"time"

	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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
