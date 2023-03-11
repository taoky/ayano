package parser

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

type NginxCombinedParser struct{}

func (p NginxCombinedParser) Parse(line string) (LogItem, error) {
	// get the first -
	delimIndex := strings.Index(line, " - ")
	if delimIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no -")
	}

	clientIP := line[:delimIndex]
	// get time within [$time_local]
	leftBracketIndex := strings.Index(line, "[")
	if leftBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no [")
	}
	rightBracketIndex := strings.Index(line, "]")
	if rightBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no ]")
	}

	localTimeString := line[leftBracketIndex+1 : rightBracketIndex]
	localTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", localTimeString)
	if err != nil {
		return LogItem{}, err
	}
	// get URL within first "$request"
	leftQuoteIndex := strings.Index(line, "\"")
	if leftQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \"")
	}
	rightQuoteIndex := strings.Index(line[leftQuoteIndex+1:], "\"")
	if rightQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" after first \"")
	}
	rightQuoteIndex += leftQuoteIndex + 1

	url := line[leftQuoteIndex+1 : rightQuoteIndex]
	// strip HTTP method in url
	splitBySpace := strings.Split(url, " ")
	if len(splitBySpace) < 2 {
		return LogItem{}, errors.New("unexpected format: URL does not have method")
	}
	url = splitBySpace[1]
	// get size ($body_bytes_sent)
	splitBySpace = strings.Split(line[rightQuoteIndex:], " ")
	if len(splitBySpace) < 3 {
		return LogItem{}, errors.New("unexpected format: not enough fields after parsing URL")
	}
	sizeString := splitBySpace[2]
	size, err := strconv.ParseUint(sizeString, 10, 64)
	if err != nil {
		return LogItem{}, err
	}
	return LogItem{
		Size:   size,
		Client: clientIP,
		Time:   localTime,
		URL:    url,
	}, nil
}
