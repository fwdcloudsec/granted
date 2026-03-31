package granted

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/common-fate/clio"
	"github.com/common-fate/clio/cliolog"
	"github.com/common-fate/glide-cli/cmd/command"
	"github.com/common-fate/useragent"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/chromemsg"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/granted/auth"
	"github.com/fwdcloudsec/granted/pkg/granted/doctor"
	"github.com/fwdcloudsec/granted/pkg/granted/middleware"
	"github.com/fwdcloudsec/granted/pkg/granted/registry"
	"github.com/fwdcloudsec/granted/pkg/granted/request"
	"github.com/fwdcloudsec/granted/pkg/granted/settings"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func GetCliApp() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("Granted version: %s\n", build.Version)
	}

	flags := []cli.Flag{
		&cli.BoolFlag{Name: "verbose", Usage: "Log debug messages"},
		&cli.StringFlag{Name: "aws-config-file"},
	}

	app := &cli.App{
		Flags:       flags,
		Name:        "granted",
		Usage:       "https://granted.dev",
		UsageText:   "granted [global options] command [command options] [arguments...]",
		Version:     build.Version,
		HideVersion: false,
		Commands: []*cli.Command{
			&DefaultBrowserCommand,
			&settings.SettingsCommand,
			&CompletionCommand,
			&TokenCommand,
			&SSOTokensCommand,
			&UninstallCommand,
			&SSOCommand,
			&CredentialsCommand,
			middleware.WithBeforeFuncs(&CredentialProcess, middleware.WithAutosync()),
			&registry.ProfileRegistryCommand,
			&ConsoleCommand,
			&login,
			&CacheCommand,
			&auth.Command,
			&request.Command,
			&doctor.Command,
		},
		// Granted may be invoked via our browser extension, which uses the Native Messaging
		// protocol to communicate with the Granted CLI. If invoked this way, the browser calls
		// the CLI with the ID of the browser extension as the first argument.
		Action: func(c *cli.Context) error {
			arg := c.Args().First()
			if strings.HasPrefix(arg, "chrome-extension://") {
				// the CLI has been invoked from our browser extension
				return HandleChromeExtensionCall(c)
			}

			// Not invoked via the browser extension, so fall back to the default
			// behaviour of showing the application help.
			return cli.ShowAppHelp(c)
		},
		EnableBashCompletion: true,
		Before: func(c *cli.Context) error {
			if c.String("aws-config-file") != "" {
				_ = os.Setenv("AWS_CONFIG_FILE", c.String("aws-config-file"))
			}
			clio.SetLevelFromEnv("GRANTED_LOG")

			grantedFolder, err := config.GrantedStateFolder()
			if err != nil {
				return err
			}

			logfilepath := path.Join(grantedFolder, "log")

			clio.SetFileLogging(cliolog.FileLoggerConfig{
				Filename: logfilepath,
			})

			zap.ReplaceGlobals(clio.G())
			if c.Bool("verbose") {
				clio.SetLevelFromString("debug")
			}
			if err := config.SetupConfigFolder(); err != nil {
				return err
			}
			// set the user agent
			c.Context = useragent.NewContext(c.Context, "granted", build.Version)

			err = chromemsg.ConfigureHost()
			if err != nil {
				clio.Debugf("error configuring Granted browser extension native messaging manifest: %s", err.Error())
			}

			return nil
		},
	}

	return app
}

var login = cli.Command{
	Name:  "login",
	Usage: "Log in to Glide [deprecated]",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "lazy", Usage: "When the lazy flag is used, a login flow will only be started when the access token is expired"},
	},
	Action: func(c *cli.Context) error {
		clio.Warn("this command is deprecated and will be removed in a future release")
		clio.Warn("use granted auth login if you are trying to authenticate with a Common Fate deployment")

		k, err := securestorage.NewCF().Storage.Keyring()
		if err != nil {
			return errors.Wrap(err, "loading keyring")
		}

		// wrap the nested CLI command with the keyring
		lf := command.LoginFlow{Keyring: k}

		return lf.LoginAction(c)
	},
}
