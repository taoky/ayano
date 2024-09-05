package parser

import (
	"math"
	"time"
)

func init() {
	newFunc := func() Parser {
		return NginxJSONParser{}
	}
	RegisterParser(ParserMeta{
		Name:        "nginx-json",
		Description: "`nginx-json` format, see README.md for details",
		F:           newFunc,
	})
	RegisterParser(ParserMeta{
		Name:        "ngx_json",
		Description: "An alias for `nginx-json`",
		Hidden:      true,
		F:           newFunc,
	})
}

type NginxJSONParser struct{}

type NginxJSONLog struct {
	Size      uint64  `json:"size"`
	Client    string  `json:"clientip"`
	Url       string  `json:"url"`
	Timestamp float64 `json:"timestamp"`
	ServerIP  string  `json:"serverip"`
}

func (p NginxJSONParser) Parse(line []byte) (LogItem, error) {
	var logItem NginxJSONLog
	err := json.Unmarshal(line, &logItem)
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
		Server: logItem.ServerIP,
	}, nil
}
