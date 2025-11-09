package util

import (
	"strconv"

	"github.com/dustin/go-humanize"
)

type SizeFlag uint64

func (s SizeFlag) String() string {
	return humanize.Bytes(uint64(s))
}

func (s *SizeFlag) Set(value string) error {
	// First try parsing as a plain number
	size, err := strconv.ParseUint(value, 10, 64)
	if err == nil {
		*s = SizeFlag(size)
		return nil
	}

	size, err = humanize.ParseBytes(value)
	if err != nil {
		return err
	}
	*s = SizeFlag(size)
	return nil
}

func (s SizeFlag) Type() string {
	return "size"
}
