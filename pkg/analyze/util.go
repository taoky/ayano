package analyze

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

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

type SortByFlag string

const (
	SortBySize     SortByFlag = "size"
	SortByRequests SortByFlag = "requests"
)

func (s SortByFlag) String() string {
	return string(s)
}

func (s *SortByFlag) Set(value string) error {
	switch value {
	case "size":
		*s = SortBySize
	case "requests", "reqs":
		*s = SortByRequests
	default:
		return errors.New(`must be one of "size" or "requests"`)
	}
	return nil
}

func (s SortByFlag) Type() string {
	return "string"
}

func (a *Analyzer) IPPrefix(ip netip.Addr) netip.Prefix {
	var clientPrefix netip.Prefix
	if ip.Is4() {
		clientPrefix = netip.PrefixFrom(ip, a.Config.PrefixV4)
	} else {
		clientPrefix = netip.PrefixFrom(ip, a.Config.PrefixV6)
	}
	return clientPrefix.Masked()
}

func TruncateURLPath(input string) string {
	count := strings.Count(input, "/")
	if count <= 2 {
		return input
	}
	parts := strings.Split(input, "/")
	return fmt.Sprintf("/%s/.../%s", parts[1], parts[count])
}
