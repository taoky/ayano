// Modified from https://github.com/golang/term/blob/5b15d269ba1f54e8da86c8aa5574253aea0c2198/term_unix.go#L22
// It only changes input flags to disable echo and canonical mode.
// BSD-3-Clause License
package tui

import (
	"log"

	"golang.org/x/sys/unix"
)

const ioctlReadTermios = unix.TCGETS

type state struct {
	termios unix.Termios
}

func makeRaw(fd int) (*state, error) {
	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		log.Println("Not a terminal. Shortcuts will be disabled.")
		return nil, nil
	}
	oldState := state{termios: *termios}

	termios.Lflag &^= unix.ECHO | unix.ICANON
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return nil, err
	}

	return &oldState, nil
}

func restore(fd int, oldState *state) error {
	if oldState == nil {
		return nil
	}
	return unix.IoctlSetTermios(fd, unix.TCSETS, &oldState.termios)
}
