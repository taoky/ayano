package main

import (
	"os"

	"github.com/taoky/ayano/cmd"
)

func main() {
	if cmd.RootCmd().Execute() != nil {
		os.Exit(1)
	}
}
