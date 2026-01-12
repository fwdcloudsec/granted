package granted

import (
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/alias"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/urfave/cli/v2"
)

var UninstallCommand = cli.Command{
	Name:  "uninstall",
	Usage: "Remove all Granted configuration",
	Action: func(c *cli.Context) error {
		withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
		in := &survey.Confirm{
			Message: "Are you sure you want to remove your Granted config?",
			Default: true,
		}
		var confirm bool
		err := survey.AskOne(in, &confirm, withStdio)
		if err != nil {
			return err
		}
		if confirm {

			err = alias.UninstallDefaultShellAlias()
			if err != nil {
				clio.Error(err.Error())
			}
			grantedFolder, err := config.GrantedFolders()
			if err != nil {
				return err
			}

			for _, dir := range grantedFolder {
				err = os.RemoveAll(dir)
				if err != nil {
					return err
				}

				clio.Successf("Removed Granted config folder %s", dir)
			}
		}
		return nil
	},
}
