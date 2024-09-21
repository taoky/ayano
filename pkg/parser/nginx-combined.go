package parser

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
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
		Description: "(Deprecated) For nginx's default `combined` format, using regular expressions",
		F:           newFuncRegex,
	})
	RegisterParser(ParserMeta{
		Name:        "combined-regex",
		Description: "(Deprecated) An alias for `nginx-combined-regex`",
		Hidden:      true,
		F:           newFuncRegex,
	})
}

const CommonLogFormat = "02/Jan/2006:15:04:05 -0700"

func clfDateParse(s []byte) time.Time {
	return clfDateParseString(string(s))
}

func clfDateParseString(s string) time.Time {
	t, _ := time.Parse(CommonLogFormat, s)
	return t
}

// Nginx escapes `"`, `\` to `\xXX`
// Apache esacpes `"`, `\` to `\"` `\\`
func findEndingDoubleQuote(data []byte) int {
	inEscape := false
	for i := 0; i < len(data); i++ {
		if inEscape {
			inEscape = false
		} else {
			if data[i] == '\\' {
				inEscape = true
			} else if data[i] == '"' {
				return i
			}
		}
	}
	return -1
}

func ParseNginxCombined(line []byte) (LogItem, error) {
	baseIdx := 0
	// get the first -
	delimIndex := bytes.IndexByte(line, '-')
	if delimIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no - (empty identity)")
	}

	clientIP := line[:delimIndex-1]
	baseIdx = delimIndex + 1
	// get time within [$time_local]
	leftBracketIndex := bytes.IndexByte(line[baseIdx:], '[')
	if leftBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no [ (datetime)")
	}
	rightBracketIndex := bytes.IndexByte(line[baseIdx+leftBracketIndex+1:], ']')
	if rightBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no ] (datetime)")
	}

	localTimeByte := line[baseIdx+leftBracketIndex+1 : baseIdx+leftBracketIndex+rightBracketIndex+1]
	// localTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(localTimeByte))
	// if err != nil {
	// 	return LogItem{}, err
	// }
	localTime := clfDateParse(localTimeByte)
	baseIdx += leftBracketIndex + rightBracketIndex + 2

	// get URL within first "$request"
	leftQuoteIndex := bytes.IndexByte(line[baseIdx:], '"')
	if leftQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" (request)")
	}
	rightQuoteIndex := findEndingDoubleQuote(line[baseIdx+leftQuoteIndex+1:])
	if rightQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" after first \" (request)")
	}

	url := line[baseIdx+leftQuoteIndex+1 : baseIdx+leftQuoteIndex+rightQuoteIndex+1]
	baseIdx += leftQuoteIndex + rightQuoteIndex + 2
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

	// get size ($body_bytes_sent)
	baseIdx += 1
	leftSpaceIndex := bytes.IndexByte(line[baseIdx:], ' ')
	if leftSpaceIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no space after $request (code)")
	}
	rightSpaceIndex := bytes.IndexByte(line[baseIdx+leftSpaceIndex+1:], ' ')
	if rightSpaceIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no space after $body_bytes_sent (size)")
	}
	sizeBytes := line[baseIdx+leftSpaceIndex+1 : baseIdx+leftSpaceIndex+rightSpaceIndex+1]
	size, err := strconv.ParseUint(string(sizeBytes), 10, 64)
	if err != nil {
		return LogItem{}, err
	}
	baseIdx += leftSpaceIndex + rightSpaceIndex + 2

	// skip referer
	leftQuoteIndex = bytes.IndexByte(line[baseIdx:], '"')
	if leftQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" (referer)")
	}
	rightQuoteIndex = findEndingDoubleQuote(line[baseIdx+leftQuoteIndex+1:])
	if rightQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" after first \" (referer)")
	}
	baseIdx += 1 + leftQuoteIndex + rightQuoteIndex + 2
	// get UA
	leftQuoteIndex = bytes.IndexByte(line[baseIdx:], '"')
	if leftQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" (user-agent)")
	}
	rightQuoteIndex = findEndingDoubleQuote(line[baseIdx+leftQuoteIndex+1:])
	if rightQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" after first \" (user-agent)")
	}
	userAgent := line[baseIdx+leftQuoteIndex+1 : baseIdx+leftQuoteIndex+rightQuoteIndex+1]
	return LogItem{
		Size:      size,
		Client:    string(clientIP),
		Time:      localTime,
		URL:       string(url),
		Useragent: string(userAgent),
	}, nil
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
