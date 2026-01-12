package granted

import (
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/browser"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/urfave/cli/v2"
)

var DefaultBrowserCommand = cli.Command{
	Name:        "browser",
	Usage:       "View the web browser that Granted uses to open cloud consoles",
	Subcommands: []*cli.Command{&SetBrowserCommand, &SetSSOBrowserCommand},
	Action: func(c *cli.Context) error {

		// return the default browser that is set
		conf, err := config.Load()
		if err != nil {
			return err
		}

		clio.Infof("Granted is using %s. To change this run `granted browser set`", conf.DefaultBrowser)

		return nil
	},
}

var SetBrowserCommand = cli.Command{
	Name:  "set",
	Usage: "Change the web browser that Granted uses to open cloud consoles",
	Flags: []cli.Flag{&cli.StringFlag{Name: "browser", Aliases: []string{"b"}, Usage: "Specify a default browser without prompts, e.g `-b firefox`, `-b chrome`"},
		&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Specify a path to the browser without prompts, requires -browser to be provided"}},
	Action: func(c *cli.Context) (err error) {
		outcome := c.String("browser")
		path := c.String("path")

		if outcome == "" {
			if path != "" {
				clio.Info("-path flag must be used with -browser flag, provided path will be ignored")
			}
			outcome, err = browser.HandleManualBrowserSelection()
			if err != nil {
				return err
			}
		}

		return browser.ConfigureBrowserSelection(outcome, path)
	},
}

var SetSSOBrowserCommand = cli.Command{
	Name:  "set-sso",
	Usage: "Change the web browser that Granted uses to sso flows",
	Flags: []cli.Flag{&cli.StringFlag{Name: "browser", Aliases: []string{"b"}, Usage: "Specify a default browser without prompts, e.g `-b firefox`, `-b chrome`"},
		&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Usage: "Specify a path to the browser without prompts, requires -browser to be provided"}},
	Action: func(c *cli.Context) (err error) {
		outcome := c.String("browser")
		path := c.String("path")
		// save the detected browser as the default
		conf, err := config.Load()
		if err != nil {
			return err
		}
		var browserPath string

		if outcome == "" {
			if path != "" {
				clio.Info("-path flag must be used with -browser flag, provided path will be ignored")
			}
			customBrowserPath, err := browser.AskAndGetBrowserPath()
			if err != nil {
				return err
			}
			browserPath = customBrowserPath

		}

		conf.CustomSSOBrowserPath = browserPath
		err = conf.Save()
		if err != nil {
			return err
		}
		clio.Successf("Granted will default to using %s for SSO flows.", browserPath)
		return nil
	},
}
