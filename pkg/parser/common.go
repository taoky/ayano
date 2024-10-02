package parser

import (
	"bytes"
	"fmt"
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
loop:
	for baseIdx := 0; baseIdx < len(line); {
		switch line[baseIdx] {
		case '"':
			quoteIdx := findEndingDoubleQuote(line[baseIdx+1:])
			if quoteIdx == -1 {
				return res, fmt.Errorf("unexpected format: unbalanced quotes [ at %d", baseIdx)
			}
			res = append(res, line[baseIdx+1:baseIdx+quoteIdx+1])
			baseIdx += quoteIdx + 2
		case '[':
			closingIdx := bytes.IndexByte(line[baseIdx+1:], ']')
			if closingIdx == -1 {
				return res, fmt.Errorf("unexpected format: unmatched [ at %d", baseIdx)
			}
			res = append(res, line[baseIdx+1:baseIdx+closingIdx+1])
			baseIdx += closingIdx + 2
		default:
			spaceIdx := bytes.IndexByte(line[baseIdx:], ' ')
			if spaceIdx == -1 {
				res = append(res, line[baseIdx:])
				break loop
			}
			res = append(res, line[baseIdx:baseIdx+spaceIdx])
			baseIdx += spaceIdx
		}
		if baseIdx < len(line) && line[baseIdx] == ' ' {
			baseIdx++
		}
	}
	return res, nil
}
