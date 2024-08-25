package parser

import (
	"bytes"
	"errors"
	"strconv"
)

func init() {
	RegisterParser("nginx-combined", func() Parser {
		return NginxCombinedParser{}
	})
	RegisterParser("combined", func() Parser {
		return NginxCombinedParser{}
	})
}

type NginxCombinedParser struct{}

func (p NginxCombinedParser) Parse(line []byte) (LogItem, error) {
	baseIdx := 0
	// get the first -
	delimIndex := bytes.IndexByte(line, '-')
	if delimIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no -")
	}

	clientIP := line[:delimIndex-1]
	baseIdx = delimIndex + 1
	// get time within [$time_local]
	leftBracketIndex := bytes.IndexByte(line[baseIdx:], '[')
	if leftBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no [")
	}
	rightBracketIndex := bytes.IndexByte(line[baseIdx+leftBracketIndex+1:], ']')
	if rightBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no ]")
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
		return LogItem{}, errors.New("unexpected format: no \"")
	}
	rightQuoteIndex := bytes.IndexByte(line[baseIdx+leftQuoteIndex+1:], '"')
	if rightQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" after first \"")
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
		return LogItem{}, errors.New("unexpected format: no space after $request")
	}
	rightSpaceIndex := bytes.IndexByte(line[baseIdx+leftSpaceIndex+1:], ' ')
	if rightSpaceIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no space after $body_bytes_sent")
	}
	sizeBytes := line[baseIdx+leftSpaceIndex+1 : baseIdx+leftSpaceIndex+rightSpaceIndex+1]

	size, err := strconv.ParseUint(string(sizeBytes), 10, 64)
	if err != nil {
		return LogItem{}, err
	}
	return LogItem{
		Size:   size,
		Client: string(clientIP),
		Time:   localTime,
		URL:    string(url),
	}, nil
}
