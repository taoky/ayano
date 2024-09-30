package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTencentCDNParser(t *testing.T) {
	as := assert.New(t)
	p, err := GetParser("tencent-cdn")
	if !(as.NoError(err) && as.NotNil(p)) {
		return
	}
	line := []byte(`20240930180135 123.45.67.8 www.example.com /wp-content/favicon.ico 6969 120 2 200 https://www.example.com/ 3 "Mozilla/5.0 () Chrome/96.0.4664.104 Mobile Safari/537.36" "(null)" GET HTTPS hit 32768`)
	log, err := p.Parse(line)
	if !as.NoError(err) {
		return
	}
	as.EqualValues(6969, log.Size)
	as.Equal("123.45.67.8", log.Client)
	as.Equal("/wp-content/favicon.ico", log.URL)
	expectedTime := time.Date(2024, 9, 30, 18, 1, 35, 0, time.Local)
	as.WithinDuration(expectedTime, log.Time, time.Microsecond)
	as.Equal("Mozilla/5.0 () Chrome/96.0.4664.104 Mobile Safari/537.36", log.Useragent)
}
