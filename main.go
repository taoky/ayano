package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	. "github.com/taoky/ayano/parser"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/dustin/go-humanize"
	"github.com/nxadm/tail"
)

var sizeStats map[string]uint64
var reqStats map[string]int
var lastURL map[string]string

// Variables for daemon mode
var lastsizeStats map[string]uint64
var oneGB uint64 = 1024 * 1024 * 1024
var firstSeenDate map[string]time.Time

// Record time of last URL change
var lastURLUpdateDate map[string]time.Time

// Record time of last URL access
var lastURLAccessDate map[string]time.Time

var statLock sync.Mutex

var topShow *int
var refreshSec *int
var absoluteItemTime *bool
var whole *bool
var noNetstat *bool
var parser *string
var threshold *string
var server *string
var analyse *bool
var daemon *bool
var logOutput *string

var logFile *os.File

var thresholdBytes uint64

var boldStart = "\u001b[1m"
var boldEnd = "\u001b[22m"

func printTopValues(displayRecord map[string]time.Time, useLock bool) {
	activeConn := make(map[string]int)
	if !*noNetstat {
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
				activeConn[getIPPrefixString(ip)] += 1
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
				activeConn[getIPPrefixString(ip)] += 1
			}
		}
	}

	// sort stats key by value
	var keys []string

	if useLock {
		statLock.Lock()
	}

	for k := range sizeStats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return sizeStats[keys[i]] > sizeStats[keys[j]]
	})
	// print top N
	top := *topShow
	if len(keys) < *topShow {
		top = len(keys)
	} else if *topShow == 0 {
		// no limit
		top = len(keys)
	}
	for i := 0; i < top; i++ {
		key := keys[i]
		total := sizeStats[key]
		reqTotal := reqStats[key]
		last := lastURL[key]

		var lastUpdateTime string
		var lastAccessTime string
		if *absoluteItemTime {
			lastUpdateTime = lastURLUpdateDate[key].Format("2006-01-02 15:04:05")
			lastAccessTime = lastURLAccessDate[key].Format("2006-01-02 15:04:05")
		} else {
			lastUpdateTime = humanize.Time(lastURLUpdateDate[key])
			lastAccessTime = humanize.Time(lastURLAccessDate[key])
		}

		average := total / uint64(reqTotal)

		fmtStart := ""
		fmtEnd := ""
		connection := ""

		boldLine := false
		if displayRecord != nil && displayRecord[key] != lastURLAccessDate[key] {
			// display this line in bold
			fmtStart = boldStart
			fmtEnd = boldEnd
			boldLine = true
		}
		if !*noNetstat {
			if _, ok := activeConn[key]; ok {
				activeString := fmt.Sprintf(" (active, %d)", activeConn[key])
				if !boldLine {
					connection = fmt.Sprintf("%s%s%s", boldStart, activeString, boldEnd)
				} else {
					connection = activeString
				}
			}
		}
		log.Printf("%s%s%s: %s %d %s %s (from %s, last accessed %s)%s\n", fmtStart, key, connection, humanize.Bytes(total), reqTotal,
			humanize.Bytes(average), last, lastUpdateTime, lastAccessTime, fmtEnd)
		if displayRecord != nil {
			displayRecord[key] = lastURLAccessDate[key]
		}
	}

	if useLock {
		statLock.Unlock()
	}
}

func printTopValuesRoutine() {
	displayRecord := make(map[string]time.Time)
	for {
		time.Sleep(time.Duration(*refreshSec) * time.Second)
		printTopValues(displayRecord, true)
		fmt.Println()
	}
}

func getIPPrefixString(ip netip.Addr) string {
	var clientPrefix netip.Prefix
	if ip.Is4() {
		clientPrefix = netip.PrefixFrom(ip, 24)
	} else {
		clientPrefix = netip.PrefixFrom(ip, 48)
	}
	clientPrefix = clientPrefix.Masked()
	return clientPrefix.String()
}

// The function that does most work, and requires profiling in analysis mode
func loop(iterator FileIterator, logParser Parser) {
	for {
		line, err := iterator.Next()
		if err != nil {
			log.Fatalln("iterator error: ", err)
		}
		if line == nil {
			break
		}
		var logItem LogItem

		logItem, err = logParser.Parse(line)
		if err != nil {
			log.Printf("parse error: %v\n", err)
			log.Printf("got line: %s\n", line)
			continue
		}
		if *server != "" && logItem.Server != *server {
			continue
		}
		size := logItem.Size
		if size <= thresholdBytes {
			continue
		}
		clientip_str := logItem.Client
		clientip, err := netip.ParseAddr(clientip_str)
		if err != nil {
			log.Printf("parse ip error: %v\n", err)
			continue
		}
		clientPrefixString := getIPPrefixString(clientip)

		if !*analyse && !*daemon {
			statLock.Lock()
		}

		sizeStats[clientPrefixString] += size
		reqStats[clientPrefixString] += 1

		url := logItem.URL
		if url != lastURL[clientPrefixString] {
			lastURL[clientPrefixString] = url
			lastURLUpdateDate[clientPrefixString] = logItem.Time
		}
		lastURLAccessDate[clientPrefixString] = logItem.Time

		if !*analyse && !*daemon {
			statLock.Unlock()
		} else if *daemon {
			delta := sizeStats[clientPrefixString] - lastsizeStats[clientPrefixString]
			printTimes := delta / oneGB
			for range printTimes {
				if lastsizeStats[clientPrefixString] == 0 {
					firstSeenDate[clientPrefixString] = logItem.Time
				}
				log.Printf("%s %s %s %s", clientPrefixString, humanize.IBytes(sizeStats[clientPrefixString]),
					firstSeenDate[clientPrefixString].Format("2006-01-02 15:04:05"), url)
				lastsizeStats[clientPrefixString] = sizeStats[clientPrefixString]
			}
		}
	}
}

func mapInit() {
	sizeStats = make(map[string]uint64)
	lastsizeStats = make(map[string]uint64)
	firstSeenDate = make(map[string]time.Time)
	reqStats = make(map[string]int)
	lastURL = make(map[string]string)
	lastURLUpdateDate = make(map[string]time.Time)
	lastURLAccessDate = make(map[string]time.Time)
}

func openFileIterator(filename string) (FileIterator, error) {
	if !*analyse {
		var seekInfo *tail.SeekInfo
		if *whole {
			seekInfo = &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekStart,
			}
		} else {
			seekInfo = &tail.SeekInfo{
				Offset: -1024 * 1024,
				Whence: io.SeekEnd,
			}
		}
		t, err := tail.TailFile(filename, tail.Config{
			Follow:        true,
			ReOpen:        true,
			Location:      seekInfo,
			CompleteLines: true,
			MustExist:     true,
		})
		if err != nil {
			return nil, err
		}
		if !*whole {
			// Eat a line from t.Lines, as first line may be incomplete
			<-t.Lines
		}
		return NewFileIteratorWithTail(t), nil
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		return NewFileIteratorWithScanner(scanner), nil
	}
}

func setLogOutput() {
	var err error
	logFile, err = os.OpenFile(*logOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
}

func main() {
	topShow = flag.Int("n", 10, "Show top N values (0 means no limit)")
	refreshSec = flag.Int("r", 5, "Refresh interval in seconds")
	absoluteItemTime = flag.Bool("absolute", false, "Show absolute time for each item")
	whole = flag.Bool("whole", false, "Analyze whole log file and then tail it")
	noNetstat = flag.Bool("no-netstat", false, "Do not detect active connections")
	parser = flag.String("parser", "nginx-json", "Parser to use (nginx-json or nginx-combined)")
	threshold = flag.String("threshold", "100M", "Threshold size for request (only requests larger than this will be counted)")
	server = flag.String("server", "", "Server IP to filter (nginx-json only)")
	analyse = flag.Bool("analyse", false, "Log analyse mode (no tail following, only show top N at the end, and implies -whole)")
	daemon = flag.Bool("daemon", false, "Daemon mode, prints out IP cidr and total size every 1GB")
	logOutput = flag.String("outlog", "", "Change log output file")
	flag.Parse()

	if *parser != "nginx-json" && *parser != "nginx-combined" {
		log.Fatal("Invalid parser")
	}

	if *logOutput != "" {
		setLogOutput()

		// setup SIGHUP to reopen log file
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		go func() {
			for sig := range c {
				if sig == syscall.SIGHUP {
					setLogOutput()
					// Let GC close the old file
					runtime.GC()
				}
			}
		}()
	}

	if *analyse {
		*whole = true
	}

	var err error
	thresholdBytes, err = humanize.ParseBytes(*threshold)
	if err != nil {
		log.Fatal("Invalid threshold (your input cannot be parsed)")
	}

	var filename string
	if len(flag.Args()) == 1 {
		filename = flag.Args()[0]
	} else {
		filename = "/var/log/nginx/mirrors/access_json.log"
	}
	fmt.Fprintln(os.Stderr, "Using log file:", filename)

	mapInit()

	iterator, err := openFileIterator(filename)
	if err != nil {
		panic(err)
	}

	if !*analyse && !*daemon {
		go printTopValuesRoutine()
	}

	var logParser Parser
	if *parser == "nginx-json" {
		logParser = NginxJSONParser{}
	} else if *parser == "nginx-combined" {
		logParser = NginxCombinedParser{}
	}

	loop(iterator, logParser)

	if *analyse {
		printTopValues(nil, false)
	}
}
