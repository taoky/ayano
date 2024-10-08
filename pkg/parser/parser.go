package parser

import (
	"errors"
	"time"
)

type LogItem struct {
	Size      uint64
	Client    string
	Time      time.Time
	URL       string
	Server    string
	Useragent string

	// Parsers wishing to discard this log item can set Discard to true.
	Discard bool
}

type Parser interface {
	Parse(line []byte) (LogItem, error)
}

type ParserFunc func(line []byte) (LogItem, error)

func (p ParserFunc) Parse(line []byte) (LogItem, error) {
	return p(line)
}

type NewFunc func() Parser

type ParserMeta struct {
	Name        string
	Description string
	Hidden      bool
	F           NewFunc
}

var (
	registry = make(map[string]ParserMeta)
)

func RegisterParser(m ParserMeta) {
	registry[m.Name] = m
}

func GetParser(name string) (Parser, error) {
	m, ok := registry[name]
	if !ok {
		return nil, errors.New(name)
	}
	return m.F(), nil
}

func All() []ParserMeta {
	result := make([]ParserMeta, 0, len(registry))
	for _, m := range registry {
		result = append(result, m)
	}
	return result
}
