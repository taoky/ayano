package cmd

import (
	"slices"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
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
		table := tablewriter.NewTable(
			cmd.OutOrStdout(),
			// Disable wrapping for both header and rows to match legacy behavior.
			tablewriter.WithHeaderAutoWrap(tw.WrapNone),
			tablewriter.WithRowAutoWrap(tw.WrapNone),
			// Header and rows are left-aligned.
			tablewriter.WithHeaderAlignment(tw.AlignLeft),
			tablewriter.WithRowAlignment(tw.AlignLeft),
			// Use two-space padding between columns.
			tablewriter.WithPadding(tw.Padding{
				Right:     "  ",
				Overwrite: true,
			}),
			// No borders or header/row separator lines.
			tablewriter.WithRendition(tw.Rendition{
				Borders: tw.BorderNone,
				Settings: tw.Settings{
					Lines:      tw.LinesNone,
					Separators: tw.SeparatorsNone,
				},
			}),
		)

		table.Header("Name", "Description")

		parsers := parser.All()
		slices.SortFunc(parsers, func(a, b parser.ParserMeta) int {
			return strings.Compare(a.Name, b.Name)
		})
		for _, p := range parsers {
			if all || !p.Hidden {
				if err := table.Append([]string{p.Name, p.Description}); err != nil {
					return err
				}
			}
		}
		if err := table.Render(); err != nil {
			return err
		}
		return nil
	}
	return cmd
}
