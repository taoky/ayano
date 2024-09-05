package cmd

import (
	"errors"
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

func filenamesFromArgs(args []string) []string {
	if len(args) == 0 {
		return []string{defaultFilename}
	}
	return args
}

func runWithConfig(cmd *cobra.Command, args []string, config analyze.AnalyzerConfig) error {
	filenames := filenamesFromArgs(args)
	// Allow multiple files only when ananlyzing and NOT daemonizing
	if !(config.Analyze && !config.Daemon) && len(filenames) != 1 {
		return errors.New("only one log file can be specified when following or daemonizing")
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Using log files:", filenames)

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

	iterator, err := analyzer.OpenFileIterator(filenames[0])
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	if !config.Analyze && !config.Daemon {
		go tui.New(analyzer).Run()
	}
	if config.Daemon {
		if err := systemd.NotifyReady(); err != nil {
			return fmt.Errorf("failed to notify systemd: %w", err)
		}
	}

	err = analyzer.RunLoop(iterator)

	for i := 1; i < len(filenames); i++ {
		if err != nil {
			break
		}
		iterator, err = analyzer.OpenFileIterator(filenames[i])
		if err != nil {
			err = fmt.Errorf("failed to open file: %w", err)
			break
		}
		err = analyzer.RunLoop(iterator)
	}

	if config.Analyze {
		analyzer.PrintTopValues(nil, config.SortBy, "")
	}
	return err
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
		Use:     "analyze [filename...]",
		Aliases: []string{"analyse"},
		Short:   "Log analyse mode (no tail following, only show top N at the end, and implies --whole)",
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
