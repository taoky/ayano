package analyze

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/nxadm/tail"
	"github.com/taoky/ayano/pkg/fileiter"
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

func (a *Analyzer) OpenTailIterator(filename string) (fileiter.Iterator, error) {
	var seekInfo *tail.SeekInfo
	if a.Config.Whole {
		seekInfo = &tail.SeekInfo{
			Offset: 0,
			Whence: io.SeekStart,
		}
	} else {
		// Workaround: In this case seek does not support to keep seek at start when file < 1MiB
		// So here we check file size first, though it could have race condition,
		// at least it's better than crashing later
		fileInfo, err := os.Stat(filename)
		if err != nil {
			return nil, err
		}
		fileSize := fileInfo.Size()
		if fileSize < oneMiB {
			// The log file is too small so let's just start from the beginning
			seekInfo = &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekStart,
			}
		} else {
			seekInfo = &tail.SeekInfo{
				Offset: -oneMiB,
				Whence: io.SeekEnd,
			}
		}
	}
	t, err := tail.TailFile(filename, tail.Config{
		Follow:        true,
		ReOpen:        true,
		Location:      seekInfo,
		CompleteLines: true,
		MustExist:     true,
	})
	if err != nil {
		return nil, err
	}
	if !a.Config.Whole {
		// Eat a line from t.Lines, as first line may be incomplete
		<-t.Lines
	}
	return fileiter.NewWithTail(t), nil
}
