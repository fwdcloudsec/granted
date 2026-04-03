package granted

import (
	"errors"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/cfcfg"
	sdkconfig "github.com/common-fate/sdk/config"
	"github.com/pkg/browser"
	"github.com/urfave/cli/v2"
)

var CFCommand = cli.Command{
	Name:        "common-fate",
	Aliases:     []string{"cf"},
	Usage:       "Interact with your Common Fate deployment",
	Subcommands: []*cli.Command{&ConsoleCommand},
}

var CFConsoleCommand = cli.Command{
	Name:  "console",
	Usage: "Open the Common Fate web console",
	Flags: []cli.Flag{&cli.StringFlag{Name: "profile", Usage: "Open the Common Fate web console for a specific profile"}},
	Action: func(c *cli.Context) error {

		ctx := c.Context
		consoleURL := ""
		profiles, err := cfaws.LoadProfiles()
		if err != nil {
			return err
		}

		profileName := c.String("profile")
		if profileName != "" {
			p, err := profiles.Profile(profileName)
			if err != nil {
				return err
			}
			url, err := cfcfg.GetCommonFateURL(p)
			if err != nil {
				return err
			}
			if url == nil {
				return errors.New("the profile exists but it is not configured with with a Common Fate console url")
			}
			consoleURL = url.String()
		} else {
			foundStartURLs := map[string]bool{}
			for _, profile := range profiles.ProfileNames {
				p, err := profiles.Profile(profile)
				if err != nil {
					return err
				}
				url, err := cfcfg.GetCommonFateURL(p)
				if err != nil {
					clio.Debug(err)
				}
				if url != nil {
					foundStartURLs[url.String()] = true
				}
			}
			keys := make([]string, 0, len(foundStartURLs))
			for k := range foundStartURLs {
				keys = append(keys, k)
			}
			if len(keys) == 0 {
				// fall back to the config file
				cfFileConfig, err := sdkconfig.LoadDefault(ctx)
				if err != nil {
					clio.Debug(fmt.Errorf("could not load profile from config file: %w", err))
					return errors.New("no Common Fate deployment urls found in your aws config or the default config file, you can setup now with 'granted login'")
				}
				consoleURL = cfFileConfig.APIURL
			}
			if len(keys) == 1 {
				consoleURL = keys[0]
			}

			err = survey.AskOne(&survey.Select{
				Message: "Please select which Common Fate deployment you would like to open: ",
				Options: keys,
			}, &consoleURL)
			if err != nil {
				return err
			}

		}

		clio.Infof("Opening the Common Fate console (%s) in your default browser...", consoleURL)

		// uses the default browser to open the console
		return browser.OpenURL(consoleURL)
	},
}
