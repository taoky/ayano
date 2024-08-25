package analyze

import (
	"bufio"
	"io"
	"os"

	"github.com/nxadm/tail"
	"github.com/taoky/ayano/pkg/fileiter"
)

const oneMiB = 1024 * 1024

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

func (a *Analyzer) OpenFileIterator(filename string) (fileiter.Iterator, error) {
	if !a.Config.Analyze {
		return a.OpenTailIterator(filename)
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		return fileiter.NewWithScanner(bufio.NewScanner(file)), nil
	}
}
