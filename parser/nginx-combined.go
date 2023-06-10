package parser

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

type NginxCombinedParser struct{}

func (p NginxCombinedParser) Parse(line []byte) (LogItem, error) {
	// TODO: avoid using string for performance
	lineStr := string(line)
	// get the first -
	delimIndex := strings.Index(lineStr, " - ")
	if delimIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no -")
	}

	clientIP := lineStr[:delimIndex]
	// get time within [$time_local]
	leftBracketIndex := strings.Index(lineStr, "[")
	if leftBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no [")
	}
	rightBracketIndex := strings.Index(lineStr, "]")
	if rightBracketIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no ]")
	}

	localTimeString := lineStr[leftBracketIndex+1 : rightBracketIndex]
	localTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", localTimeString)
	if err != nil {
		return LogItem{}, err
	}
	// get URL within first "$request"
	leftQuoteIndex := strings.Index(lineStr, "\"")
	if leftQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \"")
	}
	rightQuoteIndex := strings.Index(lineStr[leftQuoteIndex+1:], "\"")
	if rightQuoteIndex == -1 {
		return LogItem{}, errors.New("unexpected format: no \" after first \"")
	}
	rightQuoteIndex += leftQuoteIndex + 1

	url := lineStr[leftQuoteIndex+1 : rightQuoteIndex]
	// strip HTTP method in url
	splitBySpace := strings.Split(url, " ")
	if len(splitBySpace) < 2 {
		return LogItem{}, errors.New("unexpected format: URL does not have method")
	}
	url = splitBySpace[1]
	// get size ($body_bytes_sent)
	splitBySpace = strings.Split(lineStr[rightQuoteIndex:], " ")
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
