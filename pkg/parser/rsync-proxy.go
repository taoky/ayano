package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	goLogTime   = "2006/01/02 15:04:05"
	listModules = "/"
)

func init() {
	newFunc := func() Parser { return ParserFunc(ParseRsyncProxy) }
	RegisterParser(ParserMeta{
		Name:        "rsync-proxy",
		Description: "rsync-proxy's access.log",
		F:           newFunc,
	})
}

func ParseRsyncProxy(line []byte) (LogItem, error) {
	fields := strings.Fields(string(line))
	if len(fields) != 9 && len(fields) != 12 {
		return LogItem{}, fmt.Errorf("invalid format: expected 9 or 12 fields, got %d", len(fields))
	}

	logTime, err := time.ParseInLocation(goLogTime, fields[0]+" "+fields[1], time.Local)
	if err != nil {
		return LogItem{}, fmt.Errorf("invalid log time: %w", err)
	}

	logItem := LogItem{
		Client: fields[4],
		Time:   logTime,
	}

	switch fields[5] {
	case "starts":
		return LogItem{Discard: true}, nil
	case "finishes":
		logItem.URL = fields[7]
		size, err := strconv.ParseUint(strings.TrimSuffix(fields[9], ","), 10, 64)
		if err != nil {
			return logItem, fmt.Errorf("invalid size: %w", err)
		}
		logItem.Size = size
	case "requests":
		if fields[6] == "listing" {
			logItem.URL = listModules
			// chop off port
			if strings.HasPrefix(logItem.Client, "[") {
				logItem.Client = strings.TrimPrefix(logItem.Client, "[")
				logItem.Client = strings.Split(logItem.Client, "]")[0]
			} else {
				logItem.Client = strings.Split(logItem.Client, ":")[0]
			}
		} else {
			// requests non-existing module
			logItem.URL = fields[8]
		}
	}
	return logItem, nil
}
