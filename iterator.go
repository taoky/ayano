package main

import (
	"bufio"

	"github.com/nxadm/tail"
)

type FileIteratorType int

const (
	Scanner FileIteratorType = 0
	Tail    FileIteratorType = 1
)

type FileIterator struct {
	Type    FileIteratorType
	scanner *bufio.Scanner
	tail    *tail.Tail
}

func NewFileIteratorWithScanner(scanner *bufio.Scanner) *FileIterator {
	// Prepare a large buffer
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	return &FileIterator{
		Type:    Scanner,
		scanner: scanner,
	}
}

func NewFileIteratorWithTail(tail *tail.Tail) *FileIterator {
	return &FileIterator{
		Type: Tail,
		tail: tail,
	}
}

func (i FileIterator) Next() ([]byte, error) {
	switch i.Type {
	case Scanner:
		if i.scanner.Scan() {
			return i.scanner.Bytes(), nil
		} else {
			return nil, i.scanner.Err()
		}
	case Tail:
		return []byte((<-i.tail.Lines).Text), nil
	default:
		panic("unknown iterator type")
	}
}
