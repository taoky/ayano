package parser

import (
	"errors"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data/utils/jsoniter"
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

var (
	json                  = jsoniter.ConfigCompatibleWithStandardLibrary
	ErrExpectedIgnoredLog = errors.New("ignored")

	registry = make(map[string]NewFunc)
)

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
