package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/taoky/ayano/pkg/analyze"
	"github.com/taoky/ayano/pkg/fileiter"
	"github.com/taoky/ayano/pkg/systemd"
	"github.com/taoky/ayano/pkg/tui"
	"github.com/taoky/ayano/pkg/util"
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
	analyzeFn := func() {
		for _, filename := range filenames {
			err = analyzer.AnalyzeFile(filename)
			if err != nil {
				break
			}
		}
	}
	if config.DirAnalyze {
		if config.CpuProfile != "" {
			util.RunCPUProfile(config.CpuProfile, analyzeFn)
		} else {
			analyzeFn()
		}
		analyzer.DirAnalyze(nil, config.SortBy, "")
		if config.MemProfile != "" {
			util.MemProfile(config.MemProfile, "allocs")
		}
		return err
	} else if config.Analyze {
		if config.CpuProfile != "" {
			util.RunCPUProfile(config.CpuProfile, analyzeFn)
		} else {
			analyzeFn()
		}
		analyzer.PrintTopValues(nil, config.SortBy, "")
		if config.MemProfile != "" {
			util.MemProfile(config.MemProfile, "allocs")
		}
		return err
	} else {
		// Tail mode
		var iters []fileiter.Iterator
		for _, filename := range filenames {
			iter, err := analyzer.OpenTailIterator(filename)
			if err != nil {
				return err
			}
			iters = append(iters, iter)
		}

		if config.Daemon {
			if err := systemd.NotifyReady(); err != nil {
				return fmt.Errorf("failed to notify systemd: %w", err)
			}
		} else {
			go tui.New(analyzer).Run()
		}

		if len(iters) == 1 {
			return analyzer.RunLoop(iters[0])
		} else {
			return analyzer.RunLoopWithMultipleIterators(iters)
		}
	}
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [filename...]",
		Short: "Run and follow the log file(s)",
	}
	setupAnalyzeCommand(cmd, cmd.Name())
	return cmd
}

func normalizeAnalyzeFlags(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "cpuprofile":
		name = "cpuprof"
	case "memprofile":
		name = "memprof"
	}
	return pflag.NormalizedName(name)
}

// First, create a helper function to handle common command configuration
func setupAnalyzeCommand(cmd *cobra.Command, cmdType string) (analyze.AnalyzerConfig, error) {
	config := analyze.DefaultConfig()
	config.InstallFlags(cmd.Flags(), cmd.Name())
	cmd.Flags().SetNormalizeFunc(normalizeAnalyzeFlags)

	// Set the command execution function
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		switch cmdType {
		case "analyze":
			config.Analyze = true
		case "daemon":
			config.Daemon = true
		case "dir-analyze":
			config.DirAnalyze = true
		case "run":
			// nothing
		default:
			panic(fmt.Sprintf("unknown analyze mode: %s", cmdType))
		}

		return runWithConfig(cmd, args, config)
	}

	return config, nil
}

// Simplify the original command creation functions
func analyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "analyze [filename...]",
		Aliases: []string{"analyse"},
		Short:   "Log analyse mode (no tail following, only show top N at the end, and implies --whole)",
	}
	setupAnalyzeCommand(cmd, cmd.Name())
	return cmd
}

func dirAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "dir-analyze [filename...]",
		Aliases: []string{"dir-analyse"},
		Short:   "Analyze log by directory (show statistics for each first-level directory)",
	}
	setupAnalyzeCommand(cmd, cmd.Name())
	return cmd
}

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon [filename]",
		Short: "Daemon mode, prints out IP CIDR and total size every 1 GiB",
		Args:  cobra.MaximumNArgs(1),
	}
	setupAnalyzeCommand(cmd, cmd.Name())
	return cmd
}
