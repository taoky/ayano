package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/taoky/ayano/pkg/analyze"
	"github.com/taoky/ayano/pkg/systemd"
	"github.com/taoky/ayano/pkg/tui"
)

const defaultFilename = "/var/log/nginx/mirrors/access_json.log"

func filenameFromArgs(args []string) string {
	if len(args) == 0 {
		return defaultFilename
	}
	return args[0]
}

func runWithConfig(cmd *cobra.Command, args []string, config analyze.AnalyzerConfig) error {
	filename := filenameFromArgs(args)
	fmt.Fprintln(cmd.ErrOrStderr(), "Using log file:", filename)
	analyzer, err := analyze.NewAnalyzer(config)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	// setup SIGHUP to reopen log file
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			systemd.MustNotifyReloading()
			analyzer.OpenLogFile()
			// Let GC close the old file
			runtime.GC()
			systemd.MustNotifyReady()
		}
	}()

	iterator, err := analyzer.OpenFileIterator(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	if !config.Analyze && !config.Daemon {
		go tui.Tui(analyzer)
	}
	if config.Daemon {
		if err := systemd.NotifyReady(); err != nil {
			return fmt.Errorf("failed to notify systemd: %w", err)
		}
	}

	analyzer.RunLoop(iterator)

	if config.Analyze {
		analyzer.PrintTopValues(nil, config.SortBy, "")
	}
	return nil
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [filename]",
		Short: "Run and follow the log file",
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
		Use:     "analyze [filename]",
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
		Use:   "daemon [filename]",
		Short: "Daemon mode, prints out IP CIDR and total size every 1 GiB",
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
