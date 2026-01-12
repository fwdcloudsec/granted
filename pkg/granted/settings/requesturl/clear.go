package requesturl

import (
	"fmt"

	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var clearRequestURLCommand = cli.Command{
	Name:  "clear",
	Usage: "Clears the current request URL",
	Action: func(c *cli.Context) error {
		gConf, err := grantedConfig.Load()
		if err != nil {
			return errors.Wrap(err, "unable to load granted config")
		}

		gConf.AccessRequestURL = ""
		if err := gConf.Save(); err != nil {
			return errors.Wrap(err, "saving config")
		}

		fmt.Println("Successfully cleared the request URL")
		return nil

	},
}
