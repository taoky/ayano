package parser

import (
	"strconv"
	"time"
)

// Fast, hand-written date format parser for common log format (CLF)
// %d/%b/%Y:%H:%M:%S %z, for example, "10/Oct/2000:13:55:36 -0700"

var clfMonthMap = map[string]int{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
	"May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
	"Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

func clfDateParse(s []byte) time.Time {
	day, _ := strconv.Atoi(string(s[0:2]))
	month := clfMonthMap[string(s[3:6])]
	year, _ := strconv.Atoi(string(s[7:11]))
	hour, _ := strconv.Atoi(string(s[12:14]))
	minute, _ := strconv.Atoi(string(s[15:17]))
	second, _ := strconv.Atoi(string(s[18:20]))

	var timezone_sign int
	if s[21] == '-' {
		timezone_sign = -1
	} else {
		timezone_sign = 1
	}
	timezone_hour, _ := strconv.Atoi(string(s[22:24]))

	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.FixedZone("", timezone_sign*int((timezone_hour*60*60))))
}
