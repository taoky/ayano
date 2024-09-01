package tui

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/taoky/ayano/pkg/analyze"
)

type ShowMode int

const (
	TopValues ShowMode = iota
	Total
)

const helpMsg = `Available shortcuts:
t/T: print total size aggregated by server
s/S: get user input for server filtering
?: help`

type Tui struct {
	analyzer *analyze.Analyzer
	// displayRecord is used to remember latest accesses time by specific IP
	displayRecord map[netip.Prefix]time.Time
	serverFilter  string
	mode          ShowMode
	ticker        *time.Ticker
	refreshChan   chan struct{}
	inputChan     chan byte
	noPrint       atomic.Bool
}

func New(analyzer *analyze.Analyzer) *Tui {
	return &Tui{
		analyzer:      analyzer,
		displayRecord: make(map[netip.Prefix]time.Time),
		mode:          TopValues,
		ticker:        time.NewTicker(time.Duration(analyzer.Config.RefreshSec) * time.Second),
		refreshChan:   make(chan struct{}),
		inputChan:     make(chan byte),
	}
}

func (t *Tui) Run() {
	a := t.analyzer
	go t.timerRoutine()
	go t.waitForOneByte()

	for {
		select {
		case k := <-t.inputChan:
			t.handleInput(k)
		case <-t.refreshChan:
			if t.mode == TopValues {
				a.PrintTopValues(t.displayRecord, "size", t.serverFilter)
			} else {
				a.PrintTotal()
			}
			fmt.Println()
		}
	}
}

func (t *Tui) handleInput(key byte) {
	switch key {
	case 'S', 's':
		t.handleS()
	case 'T', 't':
		if t.mode == TopValues {
			t.mode = Total
			fmt.Println("Switched to showing total")
		} else {
			t.mode = TopValues
			fmt.Println("Switched to showing top values")
		}
	case '?':
		fmt.Println(helpMsg)
		fmt.Println()
	}
	go t.waitForOneByte()
}

func (t *Tui) handleS() {
	t.noPrint.Store(true)
	defer t.noPrint.Store(false)

	servers := t.analyzer.GetCurrentServers()
	if len(servers) == 1 {
		serverFmt := ""
		if len(servers[0]) > 0 {
			serverFmt = " (" + servers[0] + ")"
		}
		fmt.Printf("Only one server%s is available.\n", serverFmt)
	} else if len(servers) != 0 {
		fmt.Println("Please give the server name you want to view. Enter to remove filtering.")
		// Get all servers available
		fmt.Println("Available servers:")
		for _, s := range servers {
			fmt.Println(s)
		}
		var input string
		n, err := fmt.Scanln(&input)
		if err != nil {
			if n != 0 {
				fmt.Println("Failed to get input:", err)
			} else {
				t.serverFilter = ""
			}
		} else {
			found := false
			for _, str := range servers {
				if str == input {
					found = true
					t.serverFilter = input
					break
				}
			}
			if !found {
				fmt.Println("Input does not match existing server.")
			}
		}
	}
}
