package analyze

import (
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
	a.logger.SetOutput(logFile)
	return nil
}
