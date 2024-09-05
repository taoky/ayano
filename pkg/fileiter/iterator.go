package fileiter

import (
	"bufio"
	"io"

	"github.com/nxadm/tail"
)

type Iterator interface {
	Next() ([]byte, error)
}

type scannerIterator struct {
	scanner *bufio.Scanner
}

func NewWithScanner(r io.Reader) Iterator {
	// Prepare a large buffer
	const bufSz = 1024 * 1024
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, bufSz), bufSz)
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
