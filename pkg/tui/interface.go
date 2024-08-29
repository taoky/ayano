package tui

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/taoky/ayano/pkg/analyze"
)

type showMode int

const (
	TopValues showMode = iota
	Total
)

func Tui(a *analyze.Analyzer) {
	// displayRecord is used to remember latest accesses time by specific IP
	displayRecord := make(map[netip.Prefix]time.Time)
	serverFilter := ""
	mode := TopValues
	ticker := time.NewTicker(time.Duration(a.Config.RefreshSec) * time.Second)

	refreshChan := make(chan struct{})
	inputChan := make(chan byte)

	go timerRoutine(ticker, refreshChan)
	go waitForOneByte(inputChan)

	for {
		select {
		case k := <-inputChan:
			switch k {
			case 'S':
				fallthrough
			case 's':
				shallPrint = false
				servers := a.GetCurrentServers()
				if len(servers) == 1 {
					fmt.Println("Only one server", servers[0], "is available.")
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
							serverFilter = ""
						}
					} else {
						found := false
						for _, str := range servers {
							if str == input {
								found = true
								serverFilter = input
								break
							}
						}
						if !found {
							fmt.Println("Input does not match existing server.")
						}
					}
				}
				shallPrint = true
			case 'T':
				fallthrough
			case 't':
				if mode == TopValues {
					mode = Total
					fmt.Println("Switched to showing total")
				} else {
					mode = TopValues
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
			go waitForOneByte(inputChan)
		case <-refreshChan:
			if mode == TopValues {
				a.PrintTopValues(displayRecord, "size", serverFilter)
			} else {
				a.PrintTotal()
			}
			fmt.Println()
		}
	}
}
