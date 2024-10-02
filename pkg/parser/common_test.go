package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClfDateParse(t *testing.T) {
	expected := time.Date(2006, time.January, 2, 15, 4, 5, 0, time.FixedZone("", -7*60*60))
	assert.Equal(t, expected, clfDateParse([]byte(CommonLogFormat)))
	assert.Equal(t, expected, clfDateParseString(CommonLogFormat))
}

func TestFindEndingDoubleQuote(t *testing.T) {
	type testCase struct {
		input    []byte
		expected int
	}
	testCases := []testCase{
		{[]byte(`abc"`), 3},
		{[]byte(`ab\"c"`), 5},
		{[]byte(`ab\\c"`), 5},
		{[]byte(`ab`), -1},
	}
	for _, c := range testCases {
		assert.Equal(t, c.expected, findEndingDoubleQuote(c.input))
	}
}

func TestSplitFields(t *testing.T) {
	type testCase struct {
		line     []byte
		expected [][]byte
	}
	testCases := []testCase{
		{
			[]byte(`127.0.0.1 - - [2/Jan/2006:15:04:05 -0700] "GET /blog/2021/01/hello-world HTTP/1.1" 200 512`),
			[][]byte{
				[]byte(`127.0.0.1`),
				[]byte(`-`),
				[]byte(`-`),
				[]byte(`2/Jan/2006:15:04:05 -0700`),
				[]byte(`GET /blog/2021/01/hello-world HTTP/1.1`),
				[]byte(`200`),
				[]byte(`512`),
			},
		},
	}
	for _, c := range testCases {
		res, err := splitFields(c.line)
		if assert.NoError(t, err) {
			assert.Equal(t, c.expected, res)
		}
	}
}
