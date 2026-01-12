package requesturl

import (
	"fmt"

	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/pkg/errors"

	"github.com/urfave/cli/v2"
)

var Commands = cli.Command{
	Name:        "request-url",
	Usage:       "Set the request URL for credential_process command (connection to Granted Approvals)",
	Subcommands: []*cli.Command{&setRequestURLCommand, &clearRequestURLCommand},
	Action: func(c *cli.Context) error {
		gConf, err := grantedConfig.Load()
		if err != nil {
			return errors.Wrap(err, "unable to load granted config")
		}

		if gConf.AccessRequestURL == "" {
			fmt.Println("Request URL is not configured. You can configure by using 'granted settings request-url set <YOUR_URL>'")

			return nil
		}

		fmt.Printf("The current request URL is '%s' \n", gConf.AccessRequestURL)
		fmt.Println("You can clear the value using 'granted settings request-url clear'")
		fmt.Println("Or you can reset to another value using 'granted settings request-url set <NEW_URL>'")
		return nil
	},
}
