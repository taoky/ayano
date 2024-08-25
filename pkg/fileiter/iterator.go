package fileiter

import (
	"bufio"

	"github.com/nxadm/tail"
)

type Iterator interface {
	Next() ([]byte, error)
}

type scannerIterator struct {
	scanner *bufio.Scanner
}

func NewWithScanner(scanner *bufio.Scanner) Iterator {
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

func NewWithTail(tail *tail.Tail) Iterator {
	return &tailIterator{tail: tail}
}
