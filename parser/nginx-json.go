package parser

import (
	"encoding/json"
	"math"
	"time"
)

type NginxJSONParser struct{}

type NginxJSONLog struct {
	Size      uint64  `json:"size"`
	Client    string  `json:"clientip"`
	Url       string  `json:"url"`
	Timestamp float64 `json:"timestamp"`
}

func (p NginxJSONParser) Parse(line string) (LogItem, error) {
	var logItem NginxJSONLog
	err := json.Unmarshal([]byte(line), &logItem)
	if err != nil {
		return LogItem{}, err
	}
	sec, dec := math.Modf(logItem.Timestamp)
	t := time.Unix(int64(sec), int64(dec*1e9))
	return LogItem{
		Size:   logItem.Size,
		Client: logItem.Client,
		Time:   t,
		URL:    logItem.Url,
	}, nil
}
