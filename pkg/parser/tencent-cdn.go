package parser

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"time"
)

func init() {
	newFunc := func() Parser { return ParserFunc(ParseTencentCDN) }
	RegisterParser(ParserMeta{
		Name:        "tencent-cdn",
		Description: "Tencent CDN log format",
		F:           newFunc,
	})
	RegisterParser(ParserMeta{
		Name:        "tcdn",
		Description: "An alias for `tencent-cdn`",
		Hidden:      true,
		F:           newFunc,
	})
}

const compactDateTime = "20060102150405"

func compactDateTimeParse(s []byte) time.Time {
	return compactDateTimeParseString(string(s))
}

func compactDateTimeParseString(s string) time.Time {
	t, _ := time.ParseInLocation(compactDateTime, s, time.Local)
	return t
}

func splitFields(line []byte) ([][]byte, error) {
	res := make([][]byte, 0, 16)
	for baseIdx := 0; baseIdx < len(line); {
		if line[baseIdx] == '"' {
			quoteIdx := findEndingDoubleQuote(line[baseIdx+1:])
			if quoteIdx == -1 {
				return res, errors.New("unexpected format: unbalanced quotes")
			}
			res = append(res, line[baseIdx+1:baseIdx+quoteIdx+1])
			baseIdx += quoteIdx + 2
			if line[baseIdx] == ' ' {
				baseIdx++
			}
		} else {
			spaceIdx := bytes.IndexByte(line[baseIdx:], ' ')
			if spaceIdx == -1 {
				res = append(res, line[baseIdx:])
				break
			}
			res = append(res, line[baseIdx:baseIdx+spaceIdx])
			baseIdx += spaceIdx + 1
		}
	}
	return res, nil
}

func ParseTencentCDN(line []byte) (logItem LogItem, err error) {
	fields, err := splitFields(line)
	if err != nil {
		return logItem, err
	}
	if len(fields) != 16 {
		return logItem, fmt.Errorf("invalid format: expected 16 fields, got %d", len(fields))
	}
	size, err := strconv.ParseUint(string(fields[4]), 10, 64)
	if err != nil {
		return logItem, fmt.Errorf("invalid size %s: %w", fields[4], err)
	}
	return LogItem{
		Size:      size,
		Client:    string(fields[1]),
		Time:      compactDateTimeParse(fields[0]),
		URL:       string(fields[3]),
		Server:    string(fields[2]),
		Useragent: string(fields[10]),
	}, nil
}
