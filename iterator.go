package main

import (
	"bufio"

	"github.com/nxadm/tail"
)

type FileIterator interface {
	Next() ([]byte, error)
}

type scannerIterator struct {
	scanner *bufio.Scanner
}

func NewFileIteratorWithScanner(scanner *bufio.Scanner) FileIterator {
	// Prepare a large buffer
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	return &scannerIterator{scanner: scanner}
}

func (s *scannerIterator) Next() ([]byte, error) {
	if s.scanner.Scan() {
		return s.scanner.Bytes(), nil
	} else {
		return nil, s.scanner.Err()
	}
}

type tailIterator struct {
	tail *tail.Tail
}

func (t tailIterator) Next() ([]byte, error) {
	return []byte((<-t.tail.Lines).Text), nil
}

func NewFileIteratorWithTail(tail *tail.Tail) FileIterator {
	return &tailIterator{tail: tail}
}
