package parser

import (
	"bytes"
	"errors"
	"time"
)

const CommonLogFormat = "02/Jan/2006:15:04:05 -0700"

func clfDateParse(s []byte) time.Time {
	return clfDateParseString(string(s))
}

func clfDateParseString(s string) time.Time {
	t, _ := time.Parse(CommonLogFormat, s)
	return t
}

// Nginx escapes `"`, `\` to `\xXX`
// Apache esacpes `"`, `\` to `\"` `\\`
func findEndingDoubleQuote(data []byte) int {
	inEscape := false
	for i := 0; i < len(data); i++ {
		if inEscape {
			inEscape = false
		} else {
			if data[i] == '\\' {
				inEscape = true
			} else if data[i] == '"' {
				return i
			}
		}
	}
	return -1
}

func splitFields(line []byte) ([][]byte, error) {
	res := make([][]byte, 0, 16)
	for baseIdx := 0; baseIdx < len(line); {
		if line[baseIdx] == '"' {
			quoteIdx := findEndingDoubleQuote(line[baseIdx+1:])
			if quoteIdx == -1 {
				return res, errors.New("unexpected format: unbalanced quotes")
			}
			res = append(res, line[baseIdx+1:baseIdx+quoteIdx+1])
			baseIdx += quoteIdx + 2
			if line[baseIdx] == ' ' {
				baseIdx++
			}
		} else {
			spaceIdx := bytes.IndexByte(line[baseIdx:], ' ')
			if spaceIdx == -1 {
				res = append(res, line[baseIdx:])
				break
			}
			res = append(res, line[baseIdx:baseIdx+spaceIdx])
			baseIdx += spaceIdx + 1
		}
	}
	return res, nil
}
