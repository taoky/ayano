package analyze

import (
	"io"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/olekukonko/tablewriter"
)

type OutputContext struct {
	TopN   int
	Keys   []StatKey
	Stats  map[StatKey]IPStats
	Config AnalyzerConfig

	ActiveConn    map[netip.Prefix]int
	DisplayRecord map[netip.Prefix]time.Time
}

type Outputter interface {
	Print(w io.Writer, ctx *OutputContext) error
}

type OutputterFunc func(w io.Writer, ctx *OutputContext) error

func (f OutputterFunc) Print(w io.Writer, ctx *OutputContext) error {
	return f(w, ctx)
}

func PrintTable(w io.Writer, ctx *OutputContext) error {
	table := tablewriter.NewWriter(w)
	table.SetCenterSeparator("  ")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetAutoFormatHeaders(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetNoWhiteSpace(true)
	tAlignment := []int{
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_DEFAULT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
		tablewriter.ALIGN_RIGHT,
	}
	tHeaders := []string{"CIDR", "Conn", "Bytes", "Reqs", "Avg", "URL", "URL Since", "URL Last", "UA"}
	if ctx.Config.NoNetstat {
		tAlignment = append(tAlignment[:1], tAlignment[2:]...)
		tHeaders = append(tHeaders[:1], tHeaders[2:]...)
	}
	table.SetColumnAlignment(tAlignment)
	table.SetHeader(tHeaders)

	activeConn := ctx.ActiveConn
	displayRecord := ctx.DisplayRecord
	for i := range ctx.TopN {
		key := ctx.Keys[i]
		ipStats := ctx.Stats[key]
		total := ipStats.Size
		reqTotal := ipStats.Requests
		last := ipStats.LastURL
		agents := len(ipStats.UAStore)
		if ctx.Config.Truncate2 > 0 {
			last = TruncateURLPathLen(last, ctx.Config.Truncate2)
		} else if ctx.Config.Truncate {
			last = TruncateURLPath(last)
		}

		var lastUpdateTime, lastAccessTime string
		if ctx.Config.Absolute {
			lastUpdateTime = ipStats.LastURLUpdate.Format(TimeFormat)
			lastAccessTime = ipStats.LastURLAccess.Format(TimeFormat)
		} else {
			lastUpdateTime = humanize.Time(ipStats.LastURLUpdate)
			lastAccessTime = humanize.Time(ipStats.LastURLAccess)
		}

		average := total / uint64(reqTotal)
		boldLine := false
		if displayRecord != nil && displayRecord[key.Prefix] != ipStats.LastURLAccess {
			// display this line in bold
			boldLine = true
			displayRecord[key.Prefix] = ipStats.LastURLAccess
		}

		row := []string{
			key.Prefix.String(), "", humanize.IBytes(total), strconv.FormatUint(reqTotal, 10),
			humanize.IBytes(average), last, lastUpdateTime, lastAccessTime, strconv.Itoa(agents),
		}
		rowColors := slices.Repeat([]tablewriter.Colors{tableColorNone}, len(row))
		if boldLine {
			rowColors = slices.Repeat([]tablewriter.Colors{tableColorBold}, len(row))
		} else {
			// Bold color for 2nd column (connections)
			rowColors[1] = tableColorBold
		}

		if !ctx.Config.NoNetstat {
			if _, ok := activeConn[key.Prefix]; ok {
				row[1] = strconv.Itoa(activeConn[key.Prefix])
			}
		} else {
			// Remove connections column
			row = append(row[:1], row[2:]...)
			rowColors = append(rowColors[:1], rowColors[2:]...)
		}

		table.Rich(row, rowColors)
	}
	table.Render()
	return nil
}
