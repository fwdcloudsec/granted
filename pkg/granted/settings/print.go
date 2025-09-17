package settings

import (
	"fmt"
	"os"

	"github.com/common-fate/granted/pkg/config"
	"github.com/fatih/structs"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
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
		data := []any{
			[]string{"update-checker-api-url", c.String("update-checker-api-url")},
		}
		// display config, this uses reflection to convert the config struct to a map
		// it will always show all the values in the config without us having to update it
		for k, v := range structs.Map(cfg) {
			data = append(data, []string{k, fmt.Sprint(v)})
		}

		table := tablewriter.NewTable(os.Stderr,
			tablewriter.WithConfig(tablewriter.NewConfigBuilder().
				WithRowAutoWrap(tw.WrapNone).
				WithHeaderAutoFormat(tw.On).
				WithHeaderAlignment(tw.AlignLeft).
				WithRowAlignment(tw.AlignLeft).
				WithTrimSpace(tw.On).
				Build()),
			tablewriter.WithRendition(tw.Rendition{
				Symbols: tw.NewSymbols(tw.StyleNone),
				Borders: tw.BorderNone,
				Settings: tw.Settings{
					Separators: tw.Separators{
						BetweenRows: tw.On,
					},
				},
			}),
		)
		table.Header("SETTING", "VALUE")
		table.Bulk(data)
		table.Render()
		return nil
	},
}
