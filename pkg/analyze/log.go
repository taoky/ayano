package analyze

import (
	"log"
	"os"
)

func (a *Analyzer) OpenLogFile() error {
	if a.Config.LogOutput == "" {
		return nil
	}

	logFile, err := os.OpenFile(a.Config.LogOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	log.SetOutput(logFile)
	return nil
}
