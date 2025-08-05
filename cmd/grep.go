package cmd

import (
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
		filenames := filenamesFromArgs(args)
		fmt.Fprintln(cmd.ErrOrStderr(), "Using log files:", filenames)
		cmd.SilenceUsage = true

		g, err := grep.New(config, cmd.OutOrStdout())
		if err != nil {
			return err
		}
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
