package systemd

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func NotifyReady() error {
	return Notify("READY=1")
}

func MustNotifyReady() {
	if err := NotifyReady(); err != nil {
		panic(err)
	}
}

func getMonoTime() (uint64, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1e6 + uint64(ts.Nsec)/1e3, nil
}

func NotifyReloading() error {
	microsecs, err := getMonoTime()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("RELOADING=1\nRELOAD_TIMESTAMP=%d", microsecs)
	return Notify(msg)
}

func MustNotifyReloading() {
	if err := NotifyReloading(); err != nil {
		panic(err)
	}
}

func Notify(message string) error {
	if len(message) == 0 {
		return errors.New("requires a message")
	}
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		// If not set, nothing to do
		return nil
	}
	if name[0] != '@' && name[0] != '/' {
		return errors.New("unsupported socket type")
	}

	if name[0] == '@' {
		name = "\x00" + name[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(message))
	return err
}
