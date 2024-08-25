package parser

import (
	"math"
	"time"
)

func init() {
	RegisterParser("caddy-json", func() Parser {
		return CaddyJSONParser{}
	})
	RegisterParser("caddy", func() Parser {
		return CaddyJSONParser{}
	})
}

type CaddyJSONParser struct{}

type CaddyJsonLogRequest struct {
	RemoteIP string `json:"remote_ip"`
	ClientIP string `json:"client_ip"`
	Uri      string `json:"uri"`
}

type CaddyJsonLog struct {
	Msg       string              `json:"msg"`
	Timestamp float64             `json:"ts"` // (unix_seconds_float)
	Request   CaddyJsonLogRequest `json:"request"`
	Size      uint64              `json:"size"`
}

func (p CaddyJSONParser) Parse(line []byte) (LogItem, error) {
	var logItem CaddyJsonLog
	err := json.Unmarshal(line, &logItem)
	if err != nil {
		return LogItem{}, err
	}
	if logItem.Msg != "handled request" {
		return LogItem{}, ErrExpectedIgnoredLog
	}
	sec, dec := math.Modf(logItem.Timestamp)
	t := time.Unix(int64(sec), int64(dec*1e9))
	client := logItem.Request.ClientIP
	if client == "" {
		client = logItem.Request.RemoteIP
	}
	return LogItem{
		Size:   logItem.Size,
		Client: client,
		Time:   t,
		URL:    logItem.Request.Uri,
	}, nil
}
