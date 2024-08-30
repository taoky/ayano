package analyze

import (
	"os"
	"testing"
)

func benchmarkAnalyzeLoop(b *testing.B, parserStr string) {
	// get logPath from env
	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		b.Fatal("LOG_PATH is not set")
	}
	c := AnalyzerConfig{
		NoNetstat:  true,
		Parser:     parserStr,
		Server:     "",
		RefreshSec: 5,
		Threshold:  100 * (1 << 20),
		TopN:       20,
		Whole:      true,

		Analyze: true,
	}

	a, err := NewAnalyzer(c)
	if err != nil {
		b.Fatal(err)
	}

	t, err := a.OpenFileIterator(logPath)
	if err != nil {
		b.Fatal(err)
	}

	a.RunLoop(t)
	a.PrintTopValues(nil, "size")
}

func BenchmarkAnalyzeLoopNgxJSON(b *testing.B) {
	benchmarkAnalyzeLoop(b, "nginx-json")
}

func BenchmarkAnalyzeLoopCombined(b *testing.B) {
	benchmarkAnalyzeLoop(b, "nginx-combined")
}
