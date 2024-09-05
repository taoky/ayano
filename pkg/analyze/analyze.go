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
	Size     uint64
	Requests uint64
	LastURL  string

	// Used at daemon mode only
	LastSize  uint64
	FirstSeen time.Time

	// Record time of last URL change
	LastURLUpdate time.Time

	// Record time of last URL access
	LastURLAccess time.Time
}

func (i IPStats) UpdateWith(size uint64, url string, logtime time.Time) IPStats {
	i.Size += size
	i.Requests += 1
	if url != i.LastURL {
		i.LastURL = url
		i.LastURLUpdate = logtime
	}
	i.LastURLAccess = logtime
	return i
}

type StatKey struct {
	Server string
	Prefix netip.Prefix
}

type Analyzer struct {
	Config AnalyzerConfig

	// [server, ip prefix] -> IPStats
	stats map[StatKey]IPStats
	mu    sync.Mutex

	logParser parser.Parser
	logger    *log.Logger
}

type AnalyzerConfig struct {
	Absolute   bool
	LogOutput  string
	NoNetstat  bool
	Parser     string
	PrefixV4   int
	PrefixV6   int
	RefreshSec int
	Server     string
	SortBy     SortByFlag
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
	flags.StringVarP(&c.Parser, "parser", "p", c.Parser, "Log parser (see \"ayano list parsers\")")
	flags.IntVar(&c.PrefixV4, "prefixv4", c.PrefixV4, "Group IPv4 by prefix")
	flags.IntVar(&c.PrefixV6, "prefixv6", c.PrefixV6, "Group IPv6 by prefix")
	flags.IntVarP(&c.RefreshSec, "refresh", "r", c.RefreshSec, "Refresh interval in seconds")
	flags.StringVarP(&c.Server, "server", "s", c.Server, "Server IP to filter (nginx-json only)")
	flags.VarP(&c.SortBy, "sort-by", "S", "Sort result by (size|requests)")
	flags.VarP(&c.Threshold, "threshold", "t", "Threshold size for request (only requests at least this large will be counted)")
	flags.IntVarP(&c.TopN, "top", "n", c.TopN, "Number of top items to show")
	flags.BoolVarP(&c.Whole, "whole", "w", c.Whole, "Analyze whole log file and then tail it")
}
func (c *AnalyzerConfig) UseLock() bool {
	return !c.Analyze && !c.Daemon
}

func DefaultConfig() AnalyzerConfig {
	return AnalyzerConfig{
		Parser:     "nginx-json",
		PrefixV4:   24,
		PrefixV6:   48,
		RefreshSec: 5,
		SortBy:     SortBySize,
		Threshold:  SizeFlag(10e6),
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

	logger := log.New(os.Stdout, "", log.LstdFlags)
	if c.LogOutput != "" {
		f, err := os.OpenFile(c.LogOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file error: %w", err)
		}
		c.LogOutput = f.Name()
		logger.SetOutput(f)
	}

	return &Analyzer{
		Config:    c,
		stats:     make(map[StatKey]IPStats),
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

func (a *Analyzer) AnalyzeFile(filename string) error {
	f, err := OpenFile(filename)
	if err != nil {
		return err
	}
	if closer, ok := f.(io.Closer); ok {
		defer closer.Close()
	}
	return a.RunLoop(fileiter.NewWithScanner(f))
}

func (a *Analyzer) TailFile(filename string) error {
	iter, err := a.OpenTailIterator(filename)
	if err != nil {
		return err
	}
	return a.RunLoop(iter)
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
	clientPrefix := a.IPPrefix(clientip)

	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}

	updateStats := func(key StatKey) {
		v := a.stats[key]
		a.stats[key] = v.UpdateWith(size, logItem.URL, logItem.Time)
	}
	updateStats(StatKey{logItem.Server, clientPrefix})

	// Write it twice (to total here) when we have multiple servers
	if logItem.Server != "" {
		updateStats(StatKey{"", clientPrefix})
	}

	if a.Config.Daemon {
		// If user does not provide a Config.Server, it would be "" -> total
		// and if user provides one, logItem.Server would just equal to a.Config.Server
		ipStats := a.stats[StatKey{a.Config.Server, clientPrefix}]
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
				logItem.URL)
		}
		ipStats.LastSize += printTimes * oneGB
		// Just update [StatKey{a.Config.Server, clientPrefix}] here, as the config would not be updated runtime now
		a.stats[StatKey{a.Config.Server, clientPrefix}] = ipStats
	}

	return nil
}

func (a *Analyzer) PrintTopValues(displayRecord map[netip.Prefix]time.Time, sortBy SortByFlag, serverFilter string) {
	activeConn := make(map[netip.Prefix]int)
	if !a.Config.NoNetstat {
		// Get active connections
		tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Established
		})
		if err != nil {
			a.logger.Printf("netstat error: %v", err)
		} else {
			for _, tab := range tabs {
				ip, ok := netip.AddrFromSlice(tab.RemoteAddr.IP)
				if !ok {
					continue
				}
				activeConn[a.IPPrefix(ip)] += 1
			}
		}
		tabs, err = netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Established
		})
		if err != nil {
			a.logger.Printf("netstat error: %v", err)
		} else {
			for _, tab := range tabs {
				ip, ok := netip.AddrFromSlice(tab.RemoteAddr.IP)
				if !ok {
					continue
				}
				activeConn[a.IPPrefix(ip)] += 1
			}
		}
	}

	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}

	// sort stats key by value
	keys := make([]StatKey, 0)
	for s := range a.stats {
		if s.Server != serverFilter {
			continue
		}
		keys = append(keys, s)
	}
	sortFunc := GetSortFunc(sortBy, a.stats)
	if sortFunc != nil {
		slices.SortFunc(keys, sortFunc)
	}

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
		ipStats := a.stats[key]
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

		if displayRecord != nil && displayRecord[key.Prefix] != ipStats.LastURLAccess {
			// display this line in bold
			fmtStart = boldStart
			fmtEnd = boldEnd
			boldLine = true
		}
		if !a.Config.NoNetstat {
			if _, ok := activeConn[key.Prefix]; ok {
				activeString := fmt.Sprintf(" (%2d)", activeConn[key.Prefix])
				if !boldLine {
					connection = fmt.Sprintf("%s%s%s", boldStart, activeString, boldEnd)
				} else {
					connection = activeString
				}
			} else {
				connection = "     "
			}
		}
		a.logger.Printf("%s%16s%s: %7s %3d %7s %s (from %s, last accessed %s)%s\n", fmtStart, key.Prefix, connection, humanize.IBytes(total), reqTotal,
			humanize.IBytes(average), last, lastUpdateTime, lastAccessTime, fmtEnd)
		if displayRecord != nil {
			displayRecord[key.Prefix] = ipStats.LastURLAccess
		}
	}
}

func (a *Analyzer) GetCurrentServers() []string {
	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	servers := make(map[string]struct{})
	for sp := range a.stats {
		if sp.Server != "" {
			servers[sp.Server] = struct{}{}
		}
	}
	keys := make([]string, 0, len(servers))
	for key := range servers {
		keys = append(keys, key)
	}
	return keys
}

func (a *Analyzer) PrintTotal() {
	type kv struct {
		server string
		value  uint64
	}
	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}

	totals := make(map[string]uint64)
	for sp, value := range a.stats {
		totals[sp.Server] += value.Size
	}

	var totalSlice []kv
	for k, v := range totals {
		totalSlice = append(totalSlice, kv{k, v})
	}
	slices.SortFunc(totalSlice, func(i, j kv) int {
		return int(j.value - i.value)
	})

	for _, kv := range totalSlice {
		a.logger.Printf("%s: %s\n", kv.server, humanize.IBytes(kv.value))
	}
}
