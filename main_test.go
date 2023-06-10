package main

import (
	"os"
	"testing"

	. "github.com/taoky/ayano/parser"

	"github.com/dustin/go-humanize"
)

func ptrInit() {
	topShow = new(int)
	refreshSec = new(int)
	absoluteItemTime = new(bool)
	whole = new(bool)
	noNetstat = new(bool)
	parser = new(string)
	threshold = new(string)
	server = new(string)
	analyse = new(bool)
}

func BenchmarkAnalyseLoop(b *testing.B) {
	// get logPath from env
	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		panic("LOG_PATH is not set")
	}
	// init global vars
	mapInit()
	ptrInit()
	*topShow = 20
	*refreshSec = 5
	*absoluteItemTime = false
	*whole = true
	*noNetstat = false
	*parser = "nginx-json"
	*threshold = "100M"
	*server = ""
	*analyse = true

	var err error
	thresholdBytes, err = humanize.ParseBytes(*threshold)
	if err != nil {
		panic(err)
	}
	t, err := openTailFile(logPath)
	if err != nil {
		panic(err)
	}
	logParser := NginxJSONParser{}

	loop(t, logParser)
	printTopValues(nil, false)
}
