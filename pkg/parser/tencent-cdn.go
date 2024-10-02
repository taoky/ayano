package parser

import (
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
