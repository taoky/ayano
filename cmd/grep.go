package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/taoky/ayano/pkg/grep"
)

func grepCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grep [filename...}",
		Short: "Filter log",
	}
	config := grep.DefaultConfig()
	config.InstallFlags(cmd.Flags())
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		g, err := grep.New(config, cmd.OutOrStdout())
		if err != nil {
			return err
		}
		if g.IsEmpty() {
			return errors.New("empty filter")
		}

		filenames := filenamesFromArgs(args)
		fmt.Fprintln(cmd.ErrOrStderr(), "Using log files:", filenames)
		for _, filename := range filenames {
			err = g.GrepFile(filename)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return cmd
}
