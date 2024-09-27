package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
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
	// Sanily check
	if config.Analyze && config.Daemon {
		return errors.New("analyze mode and daemonizing are mutually exclusive")
	}

	filenames := filenamesFromArgs(args)
	// Allow multiple files only in analyze mode
	if !config.Analyze && len(filenames) != 1 {
		return errors.New("only one log file can be specified when following or daemonizing")
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Using log files:", filenames)
	cmd.SilenceUsage = true

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

	if config.Analyze {
		for _, filename := range filenames {
			err = analyzer.AnalyzeFile(filename)
			if err != nil {
				break
			}
		}
		analyzer.PrintTopValues(nil, config.SortBy, "")
		return err
	} else {
		// Tail mode
		iter, err := analyzer.OpenTailIterator(filenames[0])
		if err != nil {
			return err
		}

		if config.Daemon {
			if err := systemd.NotifyReady(); err != nil {
				return fmt.Errorf("failed to notify systemd: %w", err)
			}
		} else {
			go tui.New(analyzer).Run()
		}

		return analyzer.RunLoop(iter)
	}
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

	var cpuProf string
	var memProf string
	cmd.Flags().StringVar(&cpuProf, "cpuprof", "", "write CPU pprof data to file")
	cmd.Flags().StringVar(&memProf, "memprof", "", "write memory pprof data to file")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config.Analyze = true
		if cpuProf != "" {
			f, err := os.Create(cpuProf)
			if err != nil {
				return fmt.Errorf("failed to create CPU pprof file: %w", err)
			}
			defer f.Close()
			if err := pprof.StartCPUProfile(f); err != nil {
				return fmt.Errorf("failed to start CPU pprof: %w", err)
			}
			defer pprof.StopCPUProfile()
		}
		err := runWithConfig(cmd, args, config)
		if memProf != "" {
			f, err := os.Create(memProf)
			if err != nil {
				return fmt.Errorf("failed to create memory pprof file: %w", err)
			}
			defer f.Close()
			if err := pprof.WriteHeapProfile(f); err != nil {
				return fmt.Errorf("failed to write memory pprof: %w", err)
			}
		}
		return err
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
