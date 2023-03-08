package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/netip"
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

func printTopValues() {
	for {
		time.Sleep(5 * time.Second)
		// sort stats key by value
		var keys []string
		statLock.Lock()
		for k := range sizeStats {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return sizeStats[keys[i]] > sizeStats[keys[j]]
		})
		// print top 10
		top := 10
		if len(keys) < 10 {
			top = len(keys)
		}
		for i := 0; i < top; i++ {
			key := keys[i]
			total := sizeStats[key]
			reqTotal := reqStats[key]
			last := lastURL[key]
			lastTime := lastURLUpdateDate[key].Format("2006-01-02 15:04:05")

			average := total / uint64(reqTotal)
			log.Printf("%s: %s %d %s %s (%s)\n", key, humanize.Bytes(total), reqTotal, humanize.Bytes(average), last, lastTime)
		}
		fmt.Println()
		statLock.Unlock()
	}
}

func main() {
	sizeStats = make(map[string]uint64)
	reqStats = make(map[string]int)
	lastURL = make(map[string]string)
	lastURLUpdateDate = make(map[string]time.Time)
	t, err := tail.TailFile("/var/log/nginx/mirrors/access_json.log", tail.Config{
		Follow: true,
		ReOpen: true,
		Location: &tail.SeekInfo{
			Offset: -1024 * 1024,
			Whence: io.SeekEnd,
		},
		CompleteLines: true,
	})
	if err != nil {
		panic(err)
	}
	go printTopValues()

	// Eat a line from t.Lines, as first line may be incomplete
	<-t.Lines

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
