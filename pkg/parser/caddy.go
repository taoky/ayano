package parser

import (
	"math"
	"strings"
	"time"

	"github.com/goccy/go-json"
)

func init() {
	newFunc := func() Parser {
		return ParserFunc(ParseCaddyJSON)
	}

	RegisterParser(ParserMeta{
		Name:        "caddy-json",
		Description: "Caddy's default JSON format",
		F:           newFunc,
	})
	RegisterParser(ParserMeta{
		Name:        "caddy",
		Description: "An alias for `caddy-json`",
		Hidden:      true,
		F:           newFunc,
	})
}

type CaddyJsonLogHeader struct {
	Useragent []string `json:"User-Agent"`
}

type CaddyJsonLogRequest struct {
	RemoteIP string             `json:"remote_ip"`
	ClientIP string             `json:"client_ip"`
	Uri      string             `json:"uri"`
	Headers  CaddyJsonLogHeader `json:"headers"`
}

type CaddyJsonLog struct {
	Msg       string              `json:"msg"`
	Timestamp float64             `json:"ts"` // (unix_seconds_float)
	Request   CaddyJsonLogRequest `json:"request"`
	Size      uint64              `json:"size"`
}

func ParseCaddyJSON(line []byte) (LogItem, error) {
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
		Size:      logItem.Size,
		Client:    client,
		Time:      t,
		URL:       logItem.Request.Uri,
		Useragent: strings.Join(logItem.Request.Headers.Useragent, ", "),
	}, nil
}
