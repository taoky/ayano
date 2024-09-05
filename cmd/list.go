package cmd

import (
	"slices"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/taoky/ayano/pkg/parser"
)

func listCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <item>",
		Short: "List various items",
		Args:  cobra.NoArgs,
		RunE:  showHelp,
	}
	cmd.AddCommand(listParsersCmd())
	return cmd
}

func listParsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parsers",
		Short: "List available log parsers",
		Args:  cobra.NoArgs,
	}
	var all bool
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Show all parsers")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		table := tablewriter.NewWriter(cmd.OutOrStdout())
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(true)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowLine(false)
		table.SetRowSeparator("")
		table.SetTablePadding("  ")
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderLine(false)
		table.SetBorder(false)
		table.SetNoWhiteSpace(true)

		table.SetHeader([]string{"Name", "Description"})

		parsers := parser.All()
		slices.SortFunc(parsers, func(a, b parser.ParserMeta) int {
			return strings.Compare(a.Name, b.Name)
		})
		for _, p := range parsers {
			if all || !p.Hidden {
				table.Append([]string{p.Name, p.Description})
			}
		}
		table.Render()
		return nil
	}
	return cmd
}
