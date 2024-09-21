package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testNginxCombinedParser(t *testing.T, p Parser) {
	as := assert.New(t)
	line := `123.45.67.8 - - [12/Mar/2023:00:15:32 +0800] "GET /path/to/a/file HTTP/1.1" 200 3009 "-" ""`
	log, err := p.Parse([]byte(line))
	if as.NoError(err) {
		as.EqualValues(3009, log.Size)
		as.Equal("123.45.67.8", log.Client)
		as.Equal("/path/to/a/file", log.URL)
		expectedTime := time.Date(2023, 3, 12, 0, 15, 32, 0, time.FixedZone("CST", 8*60*60))
		as.WithinDuration(expectedTime, log.Time, 0)
		as.Equal("", log.Useragent)
	}
}

func TestNginxCombinedParser(t *testing.T) {
	testNginxCombinedParser(t, ParserFunc(ParseNginxCombined))
	testNginxCombinedParser(t, ParserFunc(ParseNginxCombinedRegex))
}

func testNginxCombinedParserWithUnusualInputs(t *testing.T, p Parser) {
	as := assert.New(t)
	line := `114.5.1.4 - - [04/Apr/2024:08:01:12 +0800] "\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x94b\x22\x06u\xBEi\xF6\xC5cA\x97eq\xF0\xD5\xD3\xE6\x08I" 400 163 "-" "-"`
	log, err := p.Parse([]byte(line))
	if as.NoError(err) {
		as.Equal(`\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x94b\x22\x06u\xBEi\xF6\xC5cA\x97eq\xF0\xD5\xD3\xE6\x08I`, log.URL)
		as.Equal(uint64(163), log.Size)
	}

	line = `114.5.1.5 - - [04/Apr/2024:09:02:13 +0800] "\x16\x03\x01\x00\xEE\x01\x00\x00\xEA\x03\x03\x9C\xB4\x92\xC5{\xE9\xEC\x18\xB1\x17\x04f\xCA\x0F\xF3\xFD\xAA\x98H\xA5N\xBC\xC9\xD7\xF8\x95.H\x15\x13\xF2\xF9 ~W\xB9\x94Qs\x01\x02\xE3c'\xA8pB\xC5\xCC\x10c\xC9\xF4\x99{\x0E1\x90\x81\xBD4J\x10y\x17\x00&\xC0+\xC0/\xC0,\xC00\xCC\xA9\xCC\xA8\xC0\x09\xC0\x13\xC0" 400 163 "-" "-"`
	log, err = p.Parse([]byte(line))
	if as.NoError(err) {
		// When the abnormal request have a space in the URL, we ignore things before the space (shall be "method")
		as.Equal(`~W\xB9\x94Qs\x01\x02\xE3c'\xA8pB\xC5\xCC\x10c\xC9\xF4\x99{\x0E1\x90\x81\xBD4J\x10y\x17\x00&\xC0+\xC0/\xC0,\xC00\xCC\xA9\xCC\xA8\xC0\x09\xC0\x13\xC0`, log.URL)
		as.Equal(uint64(163), log.Size)
	}

	// In nginx double quote is escaped as \x22, but in apache2 it's escaped as \"
	line = `172.17.0.1 - - [10/Sep/2024:21:18:44 +0000] "GET /aaaaa\"\"\" HTTP/1.1" 404 196 "http://referer.example.com/\"example/" "Useragent\"\"test"`
	log, err = p.Parse([]byte(line))
	if as.NoError(err) {
		as.Equal(`/aaaaa\"\"\"`, log.URL)
		as.Equal(`Useragent\"\"test`, log.Useragent)
	}
}

func TestNginxCombinedParserWithUnusualInputs(t *testing.T) {
	testNginxCombinedParserWithUnusualInputs(t, ParserFunc(ParseNginxCombined))
	testNginxCombinedParserWithUnusualInputs(t, ParserFunc(ParseNginxCombinedRegex))
}

func testNginxNotProperlyEscaped(t *testing.T, p Parser) {
	as := assert.New(t)
	line := `114.5.1.4 - - [01/May/2024:01:02:03 +0800] "GET /echo%20ebisyz$()\%20ziyihu\nz^xyu||a%20%23'%20&echo%20ebisyz$()\%20ziyihu\nz^xyu||a%20%23|"%20&echo%20ebisyz$()\%20ziyihu\nz^xyu||a%20%23/fonts/ HTTP/1.1" 404 178 "" "Example UA"`
	log, err := p.Parse([]byte(line))
	as.NoError(err)
	as.Equal(`/echo%20ebisyz$()\%20ziyihu\nz^xyu||a%20%23'%20&echo%20ebisyz$()\%20ziyihu\nz^xyu||a%20%23|"%20&echo%20ebisyz$()\%20ziyihu\nz^xyu||a%20%23/fonts/`, log.URL)
	as.Equal(uint64(178), log.Size)
	as.Equal("Example UA", log.Useragent)
}

func TestNginxNotProperlyEscaped(t *testing.T) {
	// Cases `"` is not escaped at all. This case would NOT be supported by ParseNginxCombined.
	testNginxNotProperlyEscaped(t, ParserFunc(ParseNginxCombinedRegex))
}
