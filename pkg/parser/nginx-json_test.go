package parser

import (
	"testing"
	"time"
)

func TestNginxJsonParser(t *testing.T) {
	p := ParserFunc(ParseNginxJSON)
	line := `{"timestamp":1678551332.293,"clientip":"123.45.67.8","serverip":"87.65.4.32","method":"GET","url":"/path/to/a/file","status":200,"size":3009,"resp_time":0.000,"http_host":"example.com","referer":"","user_agent":""}`
	log, err := p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	if log.Size != 3009 {
		t.Errorf("expected size 3009, got %d", log.Size)
	}
	if log.Client != "123.45.67.8" {
		t.Errorf("expected client 123.45.67.8, got %s", log.Client)
	}
	if log.URL != "/path/to/a/file" {
		t.Errorf("expected url /path/to/a/file, got %s", log.URL)
	}
	expectedTime := time.Unix(1678551332, 293000000)
	if expectedTime.Sub(log.Time).Abs() > time.Microsecond {
		t.Errorf("expected time %v, got %v", expectedTime, log.Time)
	}
}
