package cmd

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/taoky/ayano/pkg/analyze"
	"github.com/taoky/ayano/pkg/systemd"
)

const defaultFilename = "/var/log/nginx/mirrors/access_json.log"

func filenameFromArgs(args []string) string {
	if len(args) == 0 {
		return defaultFilename
	}
	return args[0]
}

func printTopValuesRoutine(a *analyze.Analyzer) {
	displayRecord := make(map[netip.Prefix]time.Time)
	ticker := time.NewTicker(time.Duration(a.Config.RefreshSec) * time.Second)
	for range ticker.C {
		a.PrintTopValues(displayRecord)
		fmt.Println()
	}
}

var logFile *os.File

func setLogOutput(filename string) {
	var err error
	logFile, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
}

func runWithConfig(cmd *cobra.Command, args []string, config analyze.AnalyzerConfig) error {
	if config.LogOutput != "" {
		setLogOutput(config.LogOutput)

		// setup SIGHUP to reopen log file
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		go func() {
			for range c {
				systemd.MustNotifyReloading()
				setLogOutput(config.LogOutput)
				// Let GC close the old file
				runtime.GC()
				systemd.MustNotifyReady()
			}
		}()
	}

	filename := filenameFromArgs(args)
	fmt.Fprintln(cmd.ErrOrStderr(), "Using log file:", filename)
	analyzer, err := analyze.NewAnalyzer(config)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	iterator, err := analyzer.OpenFileIterator(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	if !config.Analyze && !config.Daemon {
		go printTopValuesRoutine(analyzer)
	}
	if config.Daemon {
		if err := systemd.NotifyReady(); err != nil {
			return fmt.Errorf("failed to notify systemd: %w", err)
		}
	}

	analyzer.RunLoop(iterator)

	if config.Analyze {
		analyzer.PrintTopValues(nil)
	}
	return nil
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the server",
		Args:  cobra.MaximumNArgs(1),
	}
	config := analyze.DefaultConfig()
	config.InstallFlags(cmd.Flags())
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runWithConfig(cmd, args, config)
	}
	return cmd
}

func analyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "analyze",
		Aliases: []string{"analyse"},
		Short:   "Log analyse mode (no tail following, only show top N at the end, and implies --whole)",
		Args:    cobra.MaximumNArgs(1),
	}
	config := analyze.DefaultConfig()
	config.InstallFlags(cmd.Flags())
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config.Analyze = true
		return runWithConfig(cmd, args, config)
	}
	return cmd
}

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Daemon mode, prints out IP cidr and total size every 1 GiB",
		Args:  cobra.MaximumNArgs(1),
	}
	config := analyze.DefaultConfig()
	config.InstallFlags(cmd.Flags())
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config.Daemon = true
		return runWithConfig(cmd, args, config)
	}
	return cmd
}
