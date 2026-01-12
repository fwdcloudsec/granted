package granted

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"

	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	"github.com/fwdcloudsec/granted/pkg/assume"
	"github.com/fwdcloudsec/granted/pkg/browser"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/console"
	"github.com/fwdcloudsec/granted/pkg/forkprocess"
	"github.com/fwdcloudsec/granted/pkg/launcher"
	"github.com/urfave/cli/v2"
)

var ConsoleCommand = cli.Command{
	Name:  "console",
	Usage: "Generate an AWS console URL using credentials in the environment or with a credential process.",
	Flags: []cli.Flag{

		&cli.StringFlag{Name: "service"},
		&cli.StringFlag{Name: "region", EnvVars: []string{"AWS_REGION"}},
		&cli.StringFlag{Name: "destination", Usage: "The destination URL for the console"},
		&cli.BoolFlag{Name: "url", Usage: "Return the URL to stdout instead of launching the browser"},
		&cli.BoolFlag{Name: "firefox", Usage: "Generate the Firefox container URL"},
		&cli.StringFlag{Name: "color", Usage: "When the firefox flag is true, this specifies the color of the container tab"},
		&cli.StringFlag{Name: "icon", Usage: "When firefox flag is true, this specifies the icon of the container tab"},
		&cli.StringFlag{Name: "container-name", Usage: "When firefox flag is true, this specifies the name of the container of the container tab.", Value: "aws"},
		&cli.StringSliceFlag{Name: "browser-launch-template-arg", Usage: "Additional arguments to provide to the browser launch template command in key=value format, e.g. '--browser-launch-template-arg foo=bar"},
	},
	Action: func(c *cli.Context) error {
		ctx := c.Context
		credentials, err := cfaws.GetAWSCredentials(ctx)
		if err != nil {
			return err
		}
		con := console.AWS{
			Service:     c.String("service"),
			Region:      c.String("region"),
			Destination: c.String("destination"),
		}

		consoleURL, err := con.URL(*credentials)
		if err != nil {
			return err
		}

		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if c.Bool("firefox") || cfg.DefaultBrowser == browser.FirefoxKey || cfg.DefaultBrowser == browser.FirefoxStdoutKey {
			// transform the URL into the Firefox Tab Container format.
			consoleURL = fmt.Sprintf("ext+granted-containers:name=%s&url=%s&color=%s&icon=%s", c.String("container-name"), url.QueryEscape(consoleURL), c.String("color"), c.String("icon"))
		}

		justPrintURL := c.Bool("url") || cfg.DefaultBrowser == browser.StdoutKey || cfg.DefaultBrowser == browser.FirefoxStdoutKey
		if justPrintURL {
			// return the url via stdout through the CLI wrapper script and return early.
			fmt.Print(consoleURL)
			return nil
		}

		var l assume.Launcher
		if cfg.CustomBrowserPath == "" && cfg.DefaultBrowser != "" {
			l = launcher.Open{}
		} else if cfg.CustomBrowserPath == "" && cfg.AWSConsoleBrowserLaunchTemplate == nil {
			return errors.New("default browser not configured. run `granted browser set` to configure")
		} else {
			switch cfg.DefaultBrowser {
			case browser.ChromeKey:
				l = launcher.ChromeProfile{
					ExecutablePath: cfg.CustomBrowserPath,
				}
			case browser.BraveKey:
				l = launcher.ChromeProfile{
					ExecutablePath: cfg.CustomBrowserPath,
				}
			case browser.EdgeKey:
				l = launcher.ChromeProfile{
					ExecutablePath: cfg.CustomBrowserPath,
				}
			case browser.ChromiumKey:
				l = launcher.ChromeProfile{
					ExecutablePath: cfg.CustomBrowserPath,
				}
			case browser.VivaldiKey:
				l = launcher.ChromeProfile{
					ExecutablePath: cfg.CustomBrowserPath,
				}
			case browser.FirefoxKey:
				l = launcher.Firefox{
					ExecutablePath: cfg.CustomBrowserPath,
				}
			case browser.SafariKey:
				l = launcher.Safari{}
			case browser.CustomKey:
				l, err = launcher.CustomFromLaunchTemplate(cfg.AWSConsoleBrowserLaunchTemplate, c.StringSlice("browser-launch-template-arg"))
				if err == launcher.ErrLaunchTemplateNotConfigured {
					return errors.New("error configuring custom browser, ensure that [AWSConsoleBrowserLaunchTemplate] is specified in your Granted config file")
				}
				if err != nil {
					return err
				}
			default:
				l = launcher.Open{}
			}
		}
		// now build the actual command to run - e.g. 'firefox --new-tab <URL>'
		args, err := l.LaunchCommand(consoleURL, con.Profile)
		if err != nil {
			return fmt.Errorf("error building browser launch command: %w", err)
		}

		var startErr error
		if l.UseForkProcess() {
			clio.Debugf("running command using forkprocess: %s", args)
			cmd, err := forkprocess.New(args...)
			if err != nil {
				return err
			}
			startErr = cmd.Start()
		} else {
			clio.Debugf("running command without forkprocess: %s", args)
			cmd := exec.Command(args[0], args[1:]...)
			startErr = cmd.Start()
		}

		if startErr != nil {
			return clierr.New(fmt.Sprintf("Granted was unable to open a browser session automatically due to the following error: %s", startErr.Error()),
				// allow them to try open the url manually
				clierr.Info("You can open the browser session manually using the following url:"),
				clierr.Info(consoleURL),
			)
		}
		return nil
	},
}
