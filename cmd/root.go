package cmd

import (
	"github.com/spf13/cobra"
)

func showHelp(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

func RootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ayano",
		Short: "A simple log analysis tool for Nginx, Apache, or other web server logs",
		Args:  cobra.NoArgs,
		RunE:  showHelp,
	}
	rootCmd.AddCommand(
		runCmd(),
		analyzeCmd(),
		daemonCmd(),
		listCmd(),
	)
	return rootCmd
}
