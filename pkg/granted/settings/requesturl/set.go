package requesturl

import (
	"fmt"
	"net/url"

	"charm.land/huh/v2"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/prompt"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var setRequestURLCommand = cli.Command{
	Name:  "set",
	Usage: "Set the request URL for Common Fate",
	Action: func(c *cli.Context) error {
		var approvalsURL string
		gConf, err := grantedConfig.Load()
		if err != nil {
			return errors.Wrap(err, "unable to load granted config")
		}

		approvalsURL = c.Args().First()
		if approvalsURL == "" {
			err := prompt.Form(huh.NewInput().
				Title("What is the URL of your Common Fate deployment?").
				Description("URL for your Common Fate dashboard from where users can request access \n for e.g: https://example.com").
				Value(&approvalsURL)).Run()
			if err != nil {
				return err
			}

			if approvalsURL == "" {
				fmt.Println("Common Fate URL not provided. Command aborted.")
				return nil
			}
		}

		parsedURL, err := url.ParseRequestURI(approvalsURL)
		if err != nil {
			return errors.Wrap(err, "unable to parse provided URL with err")
		}

		gConf.AccessRequestURL = parsedURL.String()
		err = gConf.Save()
		if err != nil {
			return err
		}

		fmt.Printf("Common Fate URL has been set to '%s'\n", approvalsURL)
		return nil
	},
}
