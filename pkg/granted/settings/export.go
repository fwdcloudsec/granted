package settings

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

var ExportSettingsCommand = cli.Command{
	Name:        "export-suffix",
	Usage:       "suffix to be added when exporting credentials using granteds --export flag.",
	Subcommands: []*cli.Command{&SetExportSettingsCommand},
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.ExportCredentialSuffix != nil {
			fmt.Println(*cfg.ExportCredentialSuffix)
		}
		return nil
	},
}

var SetExportSettingsCommand = cli.Command{
	Name:  "set",
	Usage: "sets a suffix to be added when exporting credentials using granteds --export flag.",
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
		in := survey.Input{
			Message: "Exported credential suffix:",
		}
		var selection string
		clio.NewLine()
		err = testable.AskOne(&in, &selection, withStdio)
		if err != nil {
			return err
		}

		cfg.ExportCredentialSuffix = &selection
		err = cfg.Save()
		if err != nil {
			return err
		}

		clio.Successf("Set export credential suffix to: %s", selection)
		return nil

	},
}
