package settings

import (
	"fmt"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

var ProfileOrderingCommand = cli.Command{
	Name:        "profile-order",
	Usage:       "Update profile ordering when assuming",
	Subcommands: []*cli.Command{&SetProfileOrderingCommand},
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		fmt.Println(cfg.Ordering)
		return nil
	},
}

var SetProfileOrderingCommand = cli.Command{
	Name:  "set",
	Usage: "Sets the method of ordering IAM profiles in the assume method",
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		clio.NewLine()
		selection, err := testable.Select("Select filter type", []string{"Frecency", "Alphabetical"})
		if err != nil {
			return err
		}

		cfg.Ordering = selection
		err = cfg.Save()
		if err != nil {
			return err
		}

		clio.Success("Set profile ordering to: ", selection)
		return nil

	},
}
