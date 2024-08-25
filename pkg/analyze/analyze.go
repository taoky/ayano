package analyze

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"sync"

	"github.com/dustin/go-humanize"
	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/fileiter"
	"github.com/taoky/ayano/pkg/parser"
)

const oneGB = 1 << 30

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
			a.logger.Println("analyze error: %v", err)
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
				ipStats.FirstSeen.Format(DateFormat),
				url)
		}
		ipStats.LastSize = ipStats.Size
	}
	return nil
}
