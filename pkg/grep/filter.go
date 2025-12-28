package grep

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/parser"
	"github.com/taoky/ayano/pkg/util"
)

type Filter struct {
	Prefixes    []netip.Prefix
	UrlContains []string
	UAContains  []string
	TimeFrom    time.Time
	TimeTo      time.Time
	Threshold   util.SizeFlag
	Server      string
}

var timeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05",
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
	flags.StringArrayVar(&f.UAContains, "ua-contains", f.UAContains, "User-Agent substring to filter (can be specified multiple times)")
	flags.TimeVar(&f.TimeFrom, "time-from", f.TimeFrom, timeFormats, "Start time to filter (inclusive). Default value (zero) means no limit")
	flags.TimeVar(&f.TimeTo, "time-to", f.TimeTo, timeFormats, "End time to filter (inclusive). Default value (zero) means no limit")
	flags.VarP(&f.Threshold, "threshold", "t", "Threshold size for request (only requests at least this large will be counted)")
	flags.StringVarP(&f.Server, "server", "s", f.Server, "Server IP to filter (nginx-json only)")
}

func (f *Filter) IsEmpty() bool {
	return len(f.Prefixes) == 0 && len(f.UrlContains) == 0 && len(f.UAContains) == 0 && f.TimeFrom.IsZero() && f.TimeTo.IsZero() && f.Threshold == 0 && f.Server == ""
}

var (
	ErrInvalidIP     = errors.New("invalid client IP")
	ErrNoPrefixMatch = errors.New("no matching prefix")
	ErrURLNoMatch    = errors.New("URL does not match")
	ErrUANoMatch     = errors.New("User-Agent does not match")
	ErrTimeNoMatch   = errors.New("time does not match")
	ErrSizeTooSmall  = errors.New("size below threshold")
	ErrServerNoMatch = errors.New("server does not match")
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
	if len(f.UAContains) > 0 {
		uaMatch := false
		for _, substr := range f.UAContains {
			if strings.Contains(item.Useragent, substr) {
				uaMatch = true
				break
			}
		}
		if !uaMatch {
			return ErrUANoMatch
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
	if f.Threshold > 0 {
		if item.Size < uint64(f.Threshold) {
			return ErrSizeTooSmall
		}
	}
	if f.Server != "" {
		if item.Server != f.Server {
			return ErrServerNoMatch
		}
	}
	return nil
}
