package analyze

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/dustin/go-humanize"
	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/fileiter"
	"github.com/taoky/ayano/pkg/parser"
)

const (
	oneGB = 1 << 30

	boldStart = "\x1B[1m"
	boldEnd   = "\x1B[22m"

	TimeFormat = time.DateTime
)

type IPStats struct {
	Size      uint64
	Requests  uint64
	LastURL   string
	LastSize  uint64
	FirstSeen time.Time

	// Record time of last URL change
	LastURLUpdate time.Time

	// Record time of last URL access
	LastURLAccess time.Time
}

type Analyzer struct {
	Config AnalyzerConfig

	ipInfo map[netip.Prefix]IPStats
	mu     sync.Mutex

	logParser parser.Parser
	logger    *log.Logger
}

type AnalyzerConfig struct {
	Absolute   bool
	LogOutput  string
	NoNetstat  bool
	Parser     string
	RefreshSec int
	Server     string
	Threshold  SizeFlag
	TopN       int
	Whole      bool

	Analyze bool
	Daemon  bool
}

func (c *AnalyzerConfig) InstallFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&c.Absolute, "absolute", "a", c.Absolute, "Show absolute time for each item")
	flags.StringVarP(&c.LogOutput, "outlog", "o", c.LogOutput, "Change log output file")
	flags.BoolVarP(&c.NoNetstat, "no-netstat", "", c.NoNetstat, "Do not detect active connections")
	flags.IntVarP(&c.RefreshSec, "refresh", "r", c.RefreshSec, "Refresh interval in seconds")
	flags.StringVarP(&c.Server, "server", "s", c.Server, "Server IP to filter (nginx-json only)")
	flags.VarP(&c.Threshold, "threshold", "t", "Threshold size for request (only requests larger than this will be counted)")
	flags.IntVarP(&c.TopN, "top", "n", c.TopN, "Number of top items to show")
	flags.BoolVarP(&c.Whole, "whole", "w", c.Whole, "Analyze whole log file and then tail it")
}
func (c *AnalyzerConfig) UseLock() bool {
	return !c.Analyze && !c.Daemon
}

func DefaultConfig() AnalyzerConfig {
	return AnalyzerConfig{
		Parser:     "nginx-json",
		RefreshSec: 5,
		Threshold:  SizeFlag(100 * 1024 * 1024),
		TopN:       10,
	}
}

func NewAnalyzer(c AnalyzerConfig) (*Analyzer, error) {
	logParser, err := parser.GetParser(c.Parser)
	if err != nil {
		return nil, fmt.Errorf("invalid parser: %w", err)
	}

	if c.Analyze {
		c.Whole = true
	}

	logger := log.New(io.Discard, "", log.LstdFlags)
	if c.LogOutput != "" {
		f, err := os.OpenFile(c.LogOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file error: %w", err)
		}
		c.LogOutput = f.Name()
		logger = log.New(f, "", log.LstdFlags)
	}

	return &Analyzer{
		Config:    c,
		ipInfo:    make(map[netip.Prefix]IPStats),
		logParser: logParser,
		logger:    logger,
	}, nil
}

func (a *Analyzer) RunLoop(iter fileiter.Iterator) error {
	for {
		line, err := iter.Next()
		if err != nil {
			return err
		}
		if line == nil {
			break
		}
		if err := a.handleLine(line); err != nil {
			// TODO: replace with logger
			a.logger.Printf("analyze error: %v", err)
		}
	}
	return nil
}

func (a *Analyzer) handleLine(line []byte) error {
	logItem, err := a.logParser.Parse(line)
	if err != nil {
		return fmt.Errorf("parse error: %w\ngot line: %s", err, line)
	}
	if a.Config.Server != "" && logItem.Server != a.Config.Server {
		return nil
	}
	size := logItem.Size
	if size < uint64(a.Config.Threshold) {
		return nil
	}
	clientip, err := netip.ParseAddr(logItem.Client)
	if err != nil {
		return fmt.Errorf("parse ip error: %w", err)
	}
	clientPrefix := IPPrefix(clientip)

	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	ipStats := a.ipInfo[clientPrefix]

	ipStats.Size += size
	ipStats.Requests += 1

	url := logItem.URL
	if url != ipStats.LastURL {
		ipStats.LastURL = url
		ipStats.LastURLUpdate = logItem.Time
	}
	ipStats.LastURLAccess = logItem.Time

	if a.Config.Daemon {
		delta := ipStats.Size - ipStats.LastSize
		if ipStats.LastSize == 0 {
			ipStats.FirstSeen = logItem.Time
		}
		printTimes := delta / oneGB
		for range printTimes {
			a.logger.Printf("%s %s %s %s",
				clientPrefix.String(),
				humanize.IBytes(ipStats.Size),
				ipStats.FirstSeen.Format(TimeFormat),
				url)
		}
		ipStats.LastSize = ipStats.Size
	}
	a.ipInfo[clientPrefix] = ipStats
	return nil
}
func (a *Analyzer) PrintTopValues(displayRecord map[netip.Prefix]time.Time) {
	activeConn := make(map[netip.Prefix]int)
	if !a.Config.NoNetstat {
		// Get active connections
		tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Established
		})
		if err != nil {
			log.Printf("netstat error: %v", err)
		} else {
			for _, tab := range tabs {
				ip, ok := netip.AddrFromSlice(tab.RemoteAddr.IP)
				if !ok {
					continue
				}
				activeConn[IPPrefix(ip)] += 1
			}
		}
		tabs, err = netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Established
		})
		if err != nil {
			log.Printf("netstat error: %v", err)
		} else {
			for _, tab := range tabs {
				ip, ok := netip.AddrFromSlice(tab.RemoteAddr.IP)
				if !ok {
					continue
				}
				activeConn[IPPrefix(ip)] += 1
			}
		}
	}

	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}

	// sort stats key by value
	keys := make([]netip.Prefix, 0, len(a.ipInfo))
	for k := range a.ipInfo {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(l, r netip.Prefix) int {
		return int(a.ipInfo[r].Size - a.ipInfo[l].Size)
	})

	// print top N
	top := a.Config.TopN
	if len(keys) < a.Config.TopN {
		top = len(keys)
	} else if a.Config.TopN == 0 {
		// no limit
		top = len(keys)
	}

	for i := range top {
		key := keys[i]
		ipStats := a.ipInfo[key]
		total := ipStats.Size
		reqTotal := ipStats.Requests
		last := ipStats.LastURL

		var lastUpdateTime string
		var lastAccessTime string
		if a.Config.Absolute {
			lastUpdateTime = ipStats.LastURLUpdate.Format(TimeFormat)
			lastAccessTime = ipStats.LastURLAccess.Format(TimeFormat)
		} else {
			lastUpdateTime = humanize.Time(ipStats.LastURLUpdate)
			lastAccessTime = humanize.Time(ipStats.LastURLAccess)
		}

		average := total / uint64(reqTotal)

		fmtStart := ""
		fmtEnd := ""
		connection := ""
		boldLine := false

		if displayRecord != nil && displayRecord[key] != ipStats.LastURLAccess {
			// display this line in bold
			fmtStart = boldStart
			fmtEnd = boldEnd
			boldLine = true
		}
		if !a.Config.NoNetstat {
			if _, ok := activeConn[key]; ok {
				activeString := fmt.Sprintf(" (%2d)", activeConn[key])
				if !boldLine {
					connection = fmt.Sprintf("%s%s%s", boldStart, activeString, boldEnd)
				} else {
					connection = activeString
				}
			} else {
				connection = "     "
			}
		}
		log.Printf("%s%16s%s: %7s %3d %7s %s (from %s, last accessed %s)%s\n", fmtStart, key, connection, humanize.IBytes(total), reqTotal,
			humanize.IBytes(average), last, lastUpdateTime, lastAccessTime, fmtEnd)
		if displayRecord != nil {
			displayRecord[key] = ipStats.LastURLAccess
		}
	}
}
