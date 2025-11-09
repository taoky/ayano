package grep

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/parser"
)

type Filter struct {
	Prefixes    []netip.Prefix
	UrlContains []string
	TimeFrom    time.Time
	TimeTo      time.Time
}

var timeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05",
	"2006-01-02",
	"20060102150405",
}

func (f *Filter) InstallFlags(flags *pflag.FlagSet) {
	flags.Func("ip", "IP or CIDR range (can be specified multiple times)",
		func(value string) error {
			p, err := netip.ParsePrefix(value)
			if err != nil {
				return err
			}
			f.Prefixes = append(f.Prefixes, p)
			return nil
		})
	flags.StringArrayVar(&f.UrlContains, "url-contains", f.UrlContains, "URL substring to filter (can be specified multiple times)")
	flags.TimeVar(&f.TimeFrom, "time-from", f.TimeFrom, timeFormats, "Start time to filter (inclusive)")
	flags.TimeVar(&f.TimeTo, "time-to", f.TimeTo, timeFormats, "End time to filter (inclusive)")
}

func (f *Filter) IsEmpty() bool {
	return len(f.Prefixes) == 0 && len(f.UrlContains) == 0 && f.TimeFrom.IsZero() && f.TimeTo.IsZero()
}

var (
	ErrInvalidIP     = errors.New("invalid client IP")
	ErrNoPrefixMatch = errors.New("no matching prefix")
	ErrURLNoMatch    = errors.New("URL does not match")
	ErrTimeNoMatch   = errors.New("time does not match")
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
	if len(f.UrlContains) > 0 {
		urlMatch := false
		for _, substr := range f.UrlContains {
			if strings.Contains(item.URL, substr) {
				urlMatch = true
				break
			}
		}
		if !urlMatch {
			return ErrURLNoMatch
		}
	}
	if !f.TimeFrom.IsZero() {
		if item.Time.Before(f.TimeFrom) {
			return ErrTimeNoMatch
		}
	}
	if !f.TimeTo.IsZero() {
		if item.Time.After(f.TimeTo) {
			return ErrTimeNoMatch
		}
	}
	return nil
}
