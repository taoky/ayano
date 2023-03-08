package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

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

func printTopValues() {
	displayRecord := make(map[string]time.Time)
	for {
		time.Sleep(time.Duration(*refreshSec) * time.Second)
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
			if displayRecord[key] != lastURLUpdateDate[key] {
				// display this line in bold
				fmtStart = "\u001b[1m"
				fmtEnd = "\u001b[22m"
			}
			log.Printf("%s%s: %s %d %s %s (%s)%s\n", fmtStart, key, humanize.Bytes(total), reqTotal, humanize.Bytes(average), last, lastTime, fmtEnd)
			displayRecord[key] = lastURLUpdateDate[key]
		}
		fmt.Println()
		statLock.Unlock()
	}
}

func main() {
	topShow = flag.Int("n", 10, "Show top N values")
	refreshSec = flag.Int("r", 5, "Refresh interval in seconds")
	absoluteItemTime = flag.Bool("absolute", false, "Show absolute time for each item")
	whole = flag.Bool("whole", false, "Analyze whole log file and then tail it")
	flag.Parse()

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
		var logItem map[string]any
		err := json.Unmarshal([]byte(line.Text), &logItem)
		if err != nil {
			log.Printf("json unmarshal error: %v\n", err)
			log.Printf("got line: %s\n", line.Text)
			continue
		}
		size := uint64(logItem["size"].(float64))
		if size <= 100000000 {
			continue
		}
		clientip_str := logItem["clientip"].(string)
		clientip, err := netip.ParseAddr(clientip_str)
		if err != nil {
			log.Printf("parse ip error: %v\n", err)
			continue
		}
		var clientPrefix netip.Prefix
		if clientip.Is4() {
			clientPrefix = netip.PrefixFrom(clientip, 24)
		} else {
			clientPrefix = netip.PrefixFrom(clientip, 48)
		}
		clientPrefix = clientPrefix.Masked()
		statLock.Lock()
		if _, ok := sizeStats[clientPrefix.String()]; ok {
			sizeStats[clientPrefix.String()] += size
		} else {
			sizeStats[clientPrefix.String()] = size
		}
		if _, ok := reqStats[clientPrefix.String()]; ok {
			reqStats[clientPrefix.String()] += 1
		} else {
			reqStats[clientPrefix.String()] = 1
		}
		url := logItem["url"].(string)
		if url != lastURL[clientPrefix.String()] {
			lastURL[clientPrefix.String()] = url
			sec, dec := math.Modf(logItem["timestamp"].(float64))
			lastURLUpdateDate[clientPrefix.String()] = time.Unix(int64(sec), int64(dec*1e9))
		}
		statLock.Unlock()
	}
}
