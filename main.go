package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/hpcloud/tail"
)

var sizeStats map[string]uint64
var reqStats map[string]int
var lastURL map[string]string
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
		for i := 0; i < 10; i++ {
			key := keys[i]
			total := sizeStats[key]
			reqTotal := reqStats[key]
			last := lastURL[key]

			average := total / uint64(reqTotal)
			log.Printf("%s: %s %d %s %s\n", key, humanize.Bytes(total), reqTotal, humanize.Bytes(average), last)
		}
		fmt.Println()
		statLock.Unlock()
	}
}

func main() {
	sizeStats = make(map[string]uint64)
	reqStats = make(map[string]int)
	lastURL = make(map[string]string)
	t, err := tail.TailFile("/var/log/nginx/mirrors/access_json.log", tail.Config{
		Follow: true,
		ReOpen: true,
	})
	if err != nil {
		panic(err)
	}
	go printTopValues()
	for line := range t.Lines {
		var logItem map[string]any
		err := json.Unmarshal([]byte(line.Text), &logItem)
		if err != nil {
			log.Printf("json unmarshal error: %v\n", err)
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
		lastURL[clientPrefix.String()] = logItem["url"].(string)
		statLock.Unlock()
	}
}
