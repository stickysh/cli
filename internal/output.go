package internal

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"os"
)

func OutResult(header []string, data [][]string) {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t\t") // pad with tabs
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data) // Add Bulk Data

	table.Render()

}

func OutInfo(msg string) {
	color.White(msg)
}

func OutWarning(msg string) {
	red := color.New(color.FgYellow).SprintFunc()
	fmt.Printf("%s %s\n", red("Error:"), msg)
}
func OutError(msg string) {
	red := color.New(color.FgRed).SprintFunc()
	fmt.Printf("%s %s\n", red("Error:"), msg)
}
