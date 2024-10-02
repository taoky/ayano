package parser

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

func init() {
	newFunc := func() Parser { return ParserFunc(ParseNginxCombined) }
	RegisterParser(ParserMeta{
		Name:        "nginx-combined",
		Description: "For nginx's default `combined` format",
		F:           newFunc,
	})
	RegisterParser(ParserMeta{
		Name:        "combined",
		Description: "An alias for `nginx-combined`",
		Hidden:      true,
		F:           newFunc,
	})

	newFuncRegex := func() Parser { return ParserFunc(ParseNginxCombinedRegex) }
	RegisterParser(ParserMeta{
		Name:        "nginx-combined-regex",
		Description: "For nginx's default `combined` format, using regular expressions",
		F:           newFuncRegex,
	})
	RegisterParser(ParserMeta{
		Name:        "combined-regex",
		Description: "An alias for `nginx-combined-regex`",
		Hidden:      true,
		F:           newFuncRegex,
	})
}

func ParseNginxCombined(line []byte) (logItem LogItem, err error) {
	fields, err := splitFields(line)
	if err != nil {
		return logItem, err
	}
	if len(fields) != 9 {
		return logItem, fmt.Errorf("invalid format: expected 9 fields, got %d", len(fields))
	}

	if string(fields[1]) != "-" {
		return logItem, errors.New("unexpected format: no - (empty identity)")
	}

	logItem.Client = string(fields[0])
	logItem.Time = clfDateParse(fields[3])

	requestLine := fields[4]
	url := requestLine
	// strip HTTP method in url
	spaceIndex := bytes.IndexByte(url, ' ')
	if spaceIndex == -1 {
		// Some abnormal requests do not have a HTTP method
		// Sliently ignore this case
	} else {
		url = url[spaceIndex+1:]
	}
	spaceIndex = bytes.IndexByte(url, ' ')
	if spaceIndex == -1 {
		// Some abnormal requests do not have a HTTP version
		// Sliently ignore this case
	} else {
		url = url[:spaceIndex]
	}
	logItem.URL = string(url)

	sizeBytes := fields[6]
	logItem.Size, err = strconv.ParseUint(string(sizeBytes), 10, 64)
	if err != nil {
		return logItem, err
	}

	logItem.Useragent = string(fields[8])
	return
}

var nginxCombinedRe = regexp.MustCompile(
	//1       2         3          4        5      6                7     8      9                  10
	`^(\S+) - ([^[]+) \[([^]]+)\] "([^ ]+ )?([^ ]+)( HTTP/[\d.]+)?" (\d+) (\d+) "((?:[^\"]|\\.)*)" "((?:[^\"]|\\.)*)"\s*$`)

func ParseNginxCombinedRegex(line []byte) (LogItem, error) {
	m := nginxCombinedRe.FindStringSubmatch(string(line))
	if m == nil {
		return LogItem{}, errors.New("unexpected format")
	}
	size, err := strconv.ParseUint(m[8], 10, 64)
	if err != nil {
		return LogItem{}, fmt.Errorf("invalid size %s: %w", m[8], err)
	}
	return LogItem{
		Client:    m[1],
		Time:      clfDateParseString(m[3]),
		URL:       m[5],
		Size:      size,
		Useragent: m[10],
	}, nil
}
