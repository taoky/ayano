package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	. "github.com/taoky/ayano/parser"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/dustin/go-humanize"
	"github.com/nxadm/tail"
)

var sizeStats map[string]uint64
var reqStats map[string]int
var lastURL map[string]string
var lastURLUpdateDate map[string]time.Time
var statLock sync.Mutex

var topShow *int
var refreshSec *int
var absoluteItemTime *bool
var whole *bool
var noNetstat *bool
var parser *string

var boldStart = "\u001b[1m"
var boldEnd = "\u001b[22m"

func printTopValues() {
	displayRecord := make(map[string]time.Time)
	for {
		time.Sleep(time.Duration(*refreshSec) * time.Second)
		activeConn := make(map[string]bool)
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
					activeConn[getIPPrefixString(ip)] = true
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
					activeConn[getIPPrefixString(ip)] = true
				}
			}
		}

		// sort stats key by value
		var keys []string
		statLock.Lock()
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
		}
		for i := 0; i < top; i++ {
			key := keys[i]
			total := sizeStats[key]
			reqTotal := reqStats[key]
			last := lastURL[key]

			var lastTime string
			if *absoluteItemTime {
				lastTime = lastURLUpdateDate[key].Format("2006-01-02 15:04:05")
			} else {
				lastTime = humanize.Time(lastURLUpdateDate[key])
			}

			average := total / uint64(reqTotal)

			fmtStart := ""
			fmtEnd := ""
			connection := ""

			boldLine := false
			if displayRecord[key] != lastURLUpdateDate[key] {
				// display this line in bold
				fmtStart = boldStart
				fmtEnd = boldEnd
				boldLine = true
			}
			if !*noNetstat {
				if _, ok := activeConn[key]; ok {
					if !boldLine {
						connection = fmt.Sprintf("%s%s%s", boldStart, " (active)", boldEnd)
					} else {
						connection = " (active)"
					}
				}
			}
			log.Printf("%s%s%s: %s %d %s %s (%s)%s\n", fmtStart, key, connection, humanize.Bytes(total), reqTotal,
				humanize.Bytes(average), last, lastTime, fmtEnd)
			displayRecord[key] = lastURLUpdateDate[key]
		}
		fmt.Println()
		statLock.Unlock()
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

func main() {
	topShow = flag.Int("n", 10, "Show top N values")
	refreshSec = flag.Int("r", 5, "Refresh interval in seconds")
	absoluteItemTime = flag.Bool("absolute", false, "Show absolute time for each item")
	whole = flag.Bool("whole", false, "Analyze whole log file and then tail it")
	noNetstat = flag.Bool("no-netstat", false, "Do not detect active connections")
	parser = flag.String("parser", "nginx-json", "Parser to use (nginx-json or nginx-combined)")
	flag.Parse()

	if *parser != "nginx-json" && *parser != "nginx-combined" {
		log.Fatal("Invalid parser")
	}

	var filename string
	if len(flag.Args()) == 1 {
		filename = flag.Args()[0]
	} else {
		filename = "/var/log/nginx/mirrors/access_json.log"
	}
	fmt.Fprintln(os.Stderr, "Using log file:", filename)

	sizeStats = make(map[string]uint64)
	reqStats = make(map[string]int)
	lastURL = make(map[string]string)
	lastURLUpdateDate = make(map[string]time.Time)

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
	})
	if err != nil {
		panic(err)
	}
	go printTopValues()

	if !*whole {
		// Eat a line from t.Lines, as first line may be incomplete
		<-t.Lines
	}

	for line := range t.Lines {
		var logItem LogItem
		var err error
		if *parser == "nginx-json" {
			var parser NginxJSONParser
			logItem, err = parser.Parse(line.Text)
		} else if *parser == "nginx-combined" {
			var parser NginxCombinedParser
			logItem, err = parser.Parse(line.Text)
		}
		if err != nil {
			log.Printf("parse error: %v\n", err)
			log.Printf("got line: %s\n", line.Text)
			continue
		}
		size := logItem.Size
		if size <= 100000000 {
			continue
		}
		clientip_str := logItem.Client
		clientip, err := netip.ParseAddr(clientip_str)
		if err != nil {
			log.Printf("parse ip error: %v\n", err)
			continue
		}
		clientPrefixString := getIPPrefixString(clientip)
		statLock.Lock()

		sizeStats[clientPrefixString] += size
		reqStats[clientPrefixString] += 1

		url := logItem.URL
		if url != lastURL[clientPrefixString] {
			lastURL[clientPrefixString] = url
			lastURLUpdateDate[clientPrefixString] = logItem.Time
		}
		statLock.Unlock()
	}
}
