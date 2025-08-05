package grep

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/parser"
)

type Filter struct {
	Prefixes []netip.Prefix
}

func (f *Filter) InstallFlags(flags *pflag.FlagSet) {
	flags.Func("ip", "IP or CIDR range", func(value string) error {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		f.Prefixes = append(f.Prefixes, p)
		return nil
	})
}

var (
	ErrInvalidIP     = errors.New("invalid client IP")
	ErrNoPrefixMatch = errors.New("no matching prefix")
)

func (f *Filter) Match(item parser.LogItem) error {
	if len(f.Prefixes) > 0 {
		ip, err := netip.ParseAddr(item.Client)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidIP, err)
		}
		prefixMatch := false
		for _, prefix := range f.Prefixes {
			if prefix.Contains(ip) {
				prefixMatch = true
				break
			}
		}
		if !prefixMatch {
			return ErrNoPrefixMatch
		}
	}
	return nil
}
