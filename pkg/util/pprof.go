package util

import (
	"os"
	"runtime"
	"runtime/pprof"
)

func RunCPUProfile(filename string, fn func()) (err error) {
	var f *os.File
	f, err = os.Create(filename)
	if err != nil {
		return
	}
	defer func() {
		err = f.Close()
	}()
	if err = pprof.StartCPUProfile(f); err != nil {
		return
	}
	defer pprof.StopCPUProfile()
	fn()
	return
}

func MemProfile(filename, profile string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	runtime.GC()
	return pprof.Lookup("allocs").WriteTo(f, 0)
}
