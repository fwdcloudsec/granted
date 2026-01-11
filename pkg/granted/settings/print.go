package settings

import (
	"fmt"
	"os"

	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fatih/structs"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

var PrintCommand = cli.Command{
	Name:  "print",
	Usage: "List Granted Settings",
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		data := [][]string{
			{"update-checker-api-url", c.String("update-checker-api-url")},
		}
		// display config, this uses reflection to convert the config struct to a map
		// it will always show all the values in the config without us having to update it
		for k, v := range structs.Map(cfg) {
			data = append(data, []string{k, fmt.Sprint(v)})
		}

		table := tablewriter.NewWriter(os.Stderr)
		table.SetHeader([]string{"SETTING", "VALUE"})
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		table.SetRowLine(true)
		table.SetHeaderLine(false)
		table.SetBorder(false)
		table.SetTablePadding("\t")
		table.SetNoWhiteSpace(true)
		table.AppendBulk(data)
		table.Render()
		return nil
	},
}
