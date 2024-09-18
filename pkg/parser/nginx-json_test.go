package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNginxJsonParser(t *testing.T) {
	as := assert.New(t)
	p := ParserFunc(ParseNginxJSON)
	line := `{"timestamp":1678551332.293,"clientip":"123.45.67.8","serverip":"87.65.4.32","method":"GET","url":"/path/to/a/file","status":200,"size":3009,"resp_time":0.000,"http_host":"example.com","referer":"","user_agent":""}`
	log, err := p.Parse([]byte(line))
	as.NoError(err)
	as.EqualValues(3009, log.Size)
	as.Equal("123.45.67.8", log.Client)
	as.Equal("/path/to/a/file", log.URL)
	expectedTime := time.Unix(1678551332, 293000000)
	as.WithinDuration(expectedTime, log.Time, time.Microsecond)
}
