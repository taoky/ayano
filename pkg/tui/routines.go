package tui

import (
	"log"
	"os"
	"time"
)

func (t *Tui) timerRoutine() {
	t.ticker = time.NewTicker(time.Duration(t.analyzer.Config.RefreshSec) * time.Second)
	for range t.ticker.C {
		if !t.noPrint.Load() {
			t.refreshChan <- struct{}{}
		}
	}
}

func (t *Tui) waitForOneByte() {
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
	t.inputChan <- b[0]
}
