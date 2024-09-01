package tui

import (
	"log"
	"os"
	"time"
)

var shallPrint = true

func timerRoutine(ticker *time.Ticker, refreshChan chan<- struct{}) {
	for range ticker.C {
		if shallPrint {
			refreshChan <- struct{}{}
		}
	}
}

func waitForOneByte(inputChan chan<- byte) {
	oldState, err := makeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	if oldState == nil {
		return
	}
	defer restore(int(os.Stdin.Fd()), oldState)

	b := make([]byte, 1)
	n, err := os.Stdin.Read(b)
	if err != nil {
		log.Println(err)
		return
	}
	if n == 0 {
		return
	}
	inputChan <- b[0]
}
