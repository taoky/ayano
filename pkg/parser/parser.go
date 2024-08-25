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

type Parser interface {
	Parse(line []byte) (LogItem, error)
}

type NewFunc func() Parser

var registry = make(map[string]NewFunc)

func RegisterParser(name string, newFunc NewFunc) {
	registry[name] = newFunc
}

func GetParser(name string) (Parser, error) {
	newFunc, ok := registry[name]
	if !ok {
		return nil, errors.New(name)
	}
	return newFunc(), nil
}
