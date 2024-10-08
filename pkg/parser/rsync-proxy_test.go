package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRsyncProxyParser(t *testing.T) {
	as := assert.New(t)
	parser, err := GetParser("rsync-proxy")
	if !as.NoError(err) {
		return
	}

	line := `2024/10/01 00:00:00 server.go:279: client 123.45.67.89 starts requesting module ubuntu`
	log, err := parser.Parse([]byte(line))
	if as.NoError(err) {
		as.True(log.Discard)
	}

	line = `2024/10/01 00:00:00 server.go:279: client 123.45.67.89 finishes module ubuntu (sent: 1841, received: 208)`
	log, err = parser.Parse([]byte(line))
	if as.NoError(err) {
		as.False(log.Discard)
		as.Equal("123.45.67.89", log.Client)
		as.Equal("ubuntu", log.URL)
		as.EqualValues(1841, log.Size)
		expectedTime := time.Date(2024, 10, 1, 0, 0, 0, 0, time.Local)
		as.WithinDuration(expectedTime, log.Time, 0)
	}

	line = `2024/10/01 00:00:00 server.go:279: client 123.45.67.89 requests non-existing module centos`
	log, err = parser.Parse([]byte(line))
	if as.NoError(err) {
		as.False(log.Discard)
		as.Equal("123.45.67.89", log.Client)
		as.Equal("centos", log.URL)
		as.EqualValues(0, log.Size)
		expectedTime := time.Date(2024, 10, 1, 0, 0, 0, 0, time.Local)
		as.WithinDuration(expectedTime, log.Time, 0)
	}

	line = `2024/10/01 00:00:00 server.go:279: client 123.45.67.89:2333 requests listing all modules`
	log, err = parser.Parse([]byte(line))
	if as.NoError(err) {
		as.False(log.Discard)
		as.Equal("123.45.67.89", log.Client)
		as.Equal(listModules, log.URL)
		as.EqualValues(0, log.Size)
		expectedTime := time.Date(2024, 10, 1, 0, 0, 0, 0, time.Local)
		as.WithinDuration(expectedTime, log.Time, 0)
	}

	line = `2024/10/01 00:00:00 server.go:279: client [2001:db8:666:6969::1]:12345 requests listing all modules`
	log, err = parser.Parse([]byte(line))
	if as.NoError(err) {
		as.False(log.Discard)
		as.Equal("2001:db8:666:6969::1", log.Client)
		as.Equal(listModules, log.URL)
		as.EqualValues(0, log.Size)
		expectedTime := time.Date(2024, 10, 1, 0, 0, 0, 0, time.Local)
		as.WithinDuration(expectedTime, log.Time, 0)
	}
}
