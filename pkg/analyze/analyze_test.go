package analyze

import (
	"os"
	"testing"

	"github.com/taoky/ayano/pkg/grep"
	"github.com/taoky/ayano/pkg/util"
)

func benchmarkAnalyzeLoop(b *testing.B, parserStr string) {
	// get logPath from env
	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		b.Fatal("LOG_PATH is not set")
	}
	filter := grep.Filter{}
	filter.Threshold = util.SizeFlag(100 * (1 << 20))
	c := AnalyzerConfig{
		NoNetstat:  true,
		Parser:     parserStr,
		RefreshSec: 5,
		Filter:     filter,
		TopN:       20,
		Whole:      true,

		Analyze: true,
	}

	a, err := NewAnalyzer(c)
	if err != nil {
		b.Fatal(err)
	}

	err = a.AnalyzeFile(logPath)
	if err != nil {
		b.Fatal(err)
	}
	a.PrintTopValues(nil, SortBySize, "")
}

func BenchmarkAnalyzeLoopNgxJSON(b *testing.B) {
	benchmarkAnalyzeLoop(b, "nginx-json")
}

func BenchmarkAnalyzeLoopCombined(b *testing.B) {
	benchmarkAnalyzeLoop(b, "nginx-combined")
}
