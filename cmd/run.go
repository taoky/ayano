package cmd

import "github.com/spf13/cobra"

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the server",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	return cmd
}
