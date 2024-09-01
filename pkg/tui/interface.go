package tui

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/taoky/ayano/pkg/analyze"
)

type ShowMode int

const (
	TopValues ShowMode = iota
	Total
)

func Tui(a *analyze.Analyzer) {
	type TuiStatus struct {
		// displayRecord is used to remember latest accesses time by specific IP
		displayRecord map[netip.Prefix]time.Time
		serverFilter  string
		mode          ShowMode
		ticker        *time.Ticker
		refreshChan   chan struct{}
		inputChan     chan byte
	}

	status := TuiStatus{
		displayRecord: make(map[netip.Prefix]time.Time),
		serverFilter:  "",
		mode:          TopValues,
		ticker:        time.NewTicker(time.Duration(a.Config.RefreshSec) * time.Second),
		refreshChan:   make(chan struct{}),
		inputChan:     make(chan byte),
	}

	go timerRoutine(status.ticker, status.refreshChan)
	go waitForOneByte(status.inputChan)

	for {
		select {
		case k := <-status.inputChan:
			switch k {
			case 'S', 's':
				noPrint.Store(true)
				servers := a.GetCurrentServers()
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
							status.serverFilter = ""
						}
					} else {
						found := false
						for _, str := range servers {
							if str == input {
								found = true
								status.serverFilter = input
								break
							}
						}
						if !found {
							fmt.Println("Input does not match existing server.")
						}
					}
				}
				noPrint.Store(false)
			case 'T', 't':
				if status.mode == TopValues {
					status.mode = Total
					fmt.Println("Switched to showing total")
				} else {
					status.mode = TopValues
					fmt.Println("Switched to showing top values")
				}
			case '?':
				fmt.Println("Available shortcuts:")
				fmt.Println("t/T: print total size aggregated by server")
				fmt.Println("s/S: get user input for server filtering")
				fmt.Println("?: help")
				fmt.Println()
			}
			// This shall always run after input is handled.
			// Don't write "continue" above!
			go waitForOneByte(status.inputChan)
		case <-status.refreshChan:
			if status.mode == TopValues {
				a.PrintTopValues(status.displayRecord, "size", status.serverFilter)
			} else {
				a.PrintTotal()
			}
			fmt.Println()
		}
	}
}
