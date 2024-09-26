package analyze

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/fileiter"
	"github.com/taoky/ayano/pkg/parser"
)

const (
	oneGB = 1 << 30

	TimeFormat = time.DateTime
)

var (
	tableColorNone = tablewriter.Colors{}
	tableColorBold = tablewriter.Colors{tablewriter.Bold, tablewriter.FgWhiteColor}
)

type IPStats struct {
	Size     uint64
	Requests uint64
	LastURL  string

	// Used with daemon mode only
	LastSize  uint64
	FirstSeen time.Time

	// Record time of last URL change
	LastURLUpdate time.Time

	// Record time of last URL access
	LastURLAccess time.Time
}

func (i IPStats) UpdateWith(item parser.LogItem) IPStats {
	i.Size += item.Size
	i.Requests += 1
	if item.URL != i.LastURL {
		if i.LastURLUpdate.Before(item.Time) {
			i.LastURL = item.URL
			i.LastURLUpdate = item.Time
			i.LastURLAccess = item.Time
		}
	} else {
		if i.LastURLAccess.Before(item.Time) {
			i.LastURLAccess = item.Time
		}
	}
	return i
}

func (i IPStats) MergeWith(other IPStats) IPStats {
	i.Size += other.Size
	i.Requests += other.Requests
	if i.LastURL == other.LastURL {
		if other.LastURLAccess.After(i.LastURLAccess) {
			i.LastURLAccess = other.LastURLAccess
		}
		if other.LastURLUpdate.Before(i.LastURLUpdate) {
			i.LastURLUpdate = other.LastURLUpdate
		}
	} else if other.LastURLUpdate.After(i.LastURLUpdate) {
		i.LastURL = other.LastURL
		i.LastURLUpdate = other.LastURLUpdate
		i.LastURLAccess = other.LastURLAccess
	}
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
	Group      bool
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
	Truncate   bool
	Whole      bool

	Analyze bool
	Daemon  bool
}

func (c *AnalyzerConfig) InstallFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&c.Absolute, "absolute", "a", c.Absolute, "Show absolute time for each item")
	flags.BoolVarP(&c.Group, "group", "g", c.Group, "Try to group CIDRs")
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
	flags.BoolVar(&c.Truncate, "truncate", c.Truncate, "Truncate long URLs from output")
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
	if c.Analyze {
		logger.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
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
		return fmt.Errorf("parse error: %w\ngot line: %q", err, line)
	}
	return a.handleLogItem(logItem)
}

func (a *Analyzer) handleLogItem(logItem parser.LogItem) error {
	// Filter by server
	if a.Config.Server != "" && logItem.Server != a.Config.Server {
		return nil
	}

	// Filter by sent size
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
		a.stats[key] = a.stats[key].UpdateWith(logItem)
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

func (a *Analyzer) GetActiveConns(activeConn map[netip.Prefix]int) {
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

// SortedKeys returns stat keys sorted by value
func (a *Analyzer) SortedKeys(sortBy SortByFlag, serverFilter string) []StatKey {
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
	return keys
}

func (a *Analyzer) PrintTopValues(displayRecord map[netip.Prefix]time.Time, sortBy SortByFlag, serverFilter string) {
	activeConn := make(map[netip.Prefix]int)
	if !a.Config.NoNetstat {
		a.GetActiveConns(activeConn)
	}

	if a.Config.UseLock() {
		a.mu.Lock()
		defer a.mu.Unlock()
	}

	keys := a.SortedKeys(sortBy, serverFilter)

	// print top N
	top := a.Config.TopN
	if len(keys) < a.Config.TopN {
		top = len(keys)
	} else if a.Config.TopN == 0 {
		// no limit
		top = len(keys)
	}

	if a.Config.Group {
		groupedKeys := make(map[StatKey]struct{})
		for _, key := range keys {
			if key.Prefix.Bits() == 0 {
				continue
			}
			adjacentKey := StatKey{key.Server, AdjacentPrefix(key.Prefix)}
			_, ok := groupedKeys[adjacentKey]
			if !ok {
				// would insert into groupedKeys
				if len(groupedKeys) >= top {
					break
				}
				groupedKeys[key] = struct{}{}
			}
			for ok {
				newStat := a.stats[key].MergeWith(a.stats[adjacentKey])
				mergedPrefix := netip.PrefixFrom(key.Prefix.Addr(), key.Prefix.Bits()-1).Masked()
				newKey := StatKey{key.Server, mergedPrefix}

				a.stats[newKey] = newStat
				delete(a.stats, key)
				delete(a.stats, adjacentKey)

				groupedKeys[newKey] = struct{}{}
				delete(groupedKeys, key)
				delete(groupedKeys, adjacentKey)

				if newKey.Prefix.Bits() == 0 {
					break
				}
				key = newKey
				adjacentKey = StatKey{key.Server, AdjacentPrefix(key.Prefix)}
				_, ok = groupedKeys[adjacentKey]
			}
		}
		keys = a.SortedKeys(sortBy, serverFilter)
		if len(keys) < top {
			top = len(keys)
		}
	}

	tableStr := new(strings.Builder)
	table := tablewriter.NewWriter(tableStr)
	table.SetCenterSeparator("  ")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetNoWhiteSpace(true)
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_DEFAULT,
		tablewriter.ALIGN_DEFAULT,
		tablewriter.ALIGN_DEFAULT,
	})
	table.SetHeader([]string{"CIDR", "Conn", "Bytes", "Reqs", "Avg", "URL", "URL Since", "URL Last"})

	for i := range top {
		key := keys[i]
		ipStats := a.stats[key]
		total := ipStats.Size
		reqTotal := ipStats.Requests
		last := ipStats.LastURL
		if a.Config.Truncate {
			last = TruncateURLPath(last)
		}

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

		connection := ""
		boldLine := false

		if displayRecord != nil && displayRecord[key.Prefix] != ipStats.LastURLAccess {
			// display this line in bold
			boldLine = true
		}
		if !a.Config.NoNetstat {
			if _, ok := activeConn[key.Prefix]; ok {
				connection = fmt.Sprintf("(%2d)", activeConn[key.Prefix])
			} else {
				connection = "     "
			}
		}
		row := []string{
			key.Prefix.String(), connection, humanize.IBytes(total), strconv.FormatUint(reqTotal, 10),
			humanize.IBytes(average), last, lastUpdateTime, lastAccessTime,
		}
		if boldLine {
			table.Rich(row, slices.Repeat([]tablewriter.Colors{tableColorNone}, len(row)))
		} else {
			table.Rich(row, slices.Concat(
				// Bold color for 2nd column (connections)
				[]tablewriter.Colors{tableColorNone, tableColorBold},
				slices.Repeat([]tablewriter.Colors{tableColorNone}, len(row)-2),
			))
		}
		if displayRecord != nil {
			displayRecord[key.Prefix] = ipStats.LastURLAccess
		}
	}
	table.Render()
	a.logger.Print(tableStr.String())
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
