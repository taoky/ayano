package util

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const oneMiB = 1024 * 1024

type filteredReader struct {
	cmd *exec.Cmd
	r   io.ReadCloser
}

func (fr *filteredReader) Read(p []byte) (n int, err error) {
	return fr.r.Read(p)
}

func (fr *filteredReader) Close() error {
	return errors.Join(fr.cmd.Wait(), fr.r.Close())
}

func filterByCommand(r io.Reader, args []string) (io.ReadCloser, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = r
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &filteredReader{cmd: cmd, r: stdout}, nil
}

type filterFunc func(r io.ReadCloser) (io.ReadCloser, error)

var fileTypes = map[string]filterFunc{
	".gz": func(r io.ReadCloser) (io.ReadCloser, error) {
		return filterByCommand(r, []string{"gzip", "-cd"})
	},
	".xz": func(r io.ReadCloser) (io.ReadCloser, error) {
		return filterByCommand(r, []string{"xz", "-cd", "-T", "0"})
	},
	".zst": func(r io.ReadCloser) (io.ReadCloser, error) {
		return filterByCommand(r, []string{"zstd", "-cd", "-T0"})
	},
}

func OpenFile(filename string) (io.ReadCloser, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	if filter, ok := fileTypes[filepath.Ext(filename)]; ok {
		return filter(f)
	}
	return f, nil
}
