package assume

import (
	"fmt"
	"os"
	"path"

	"github.com/common-fate/clio"
	"github.com/common-fate/clio/cliolog"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/alias"
	"github.com/fwdcloudsec/granted/pkg/assumeprint"
	"github.com/fwdcloudsec/granted/pkg/autosync"
	"github.com/fwdcloudsec/granted/pkg/browser"
	"github.com/fwdcloudsec/granted/pkg/chromemsg"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

// Prevent issues where these flags are initialised in some part of the program then used by another part
// For our use case, we need fresh copies of these flags in the app and in the assume command
// we use this to allow flags to be set on either side of the profile arg e.g `assume -c profile-name -r ap-southeast-2`
func GlobalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "console", Aliases: []string{"c"}, Usage: "Open a web console to the role"},
		&cli.BoolFlag{Name: "terminal", Aliases: []string{"t"}, Usage: "Use this with '-c' to open a console session and export credentials into the terminal at the same time."},
		&cli.BoolFlag{Name: "env", Aliases: []string{"e"}, Usage: "Export credentials to a .env file"},
		&cli.BoolFlag{Name: "export", Aliases: []string{"ex"}, Usage: "Export credentials to a ~/.aws/credentials file"},
		&cli.BoolFlag{Name: "export-sso-token", Aliases: []string{"es"}, Usage: "Export sso token to ~/.aws/sso/cache"},
		&cli.BoolFlag{Name: "unset", Aliases: []string{"un"}, Usage: "Unset all environment variables configured by Assume"},
		&cli.BoolFlag{Name: "url", Aliases: []string{"u"}, Usage: "Get an active console session url"},
		&cli.StringFlag{Name: "service", Aliases: []string{"s"}, Usage: "Like --c, but opens to a specified service"},
		&cli.StringFlag{Name: "region", Aliases: []string{"r"}, Usage: "region to launch the console or export to the terminal"},
		&cli.StringFlag{Name: "console-destination", Aliases: []string{"cd"}, Usage: "Open a web console at this destination"},
		&cli.StringSliceFlag{Name: "pass-through", Aliases: []string{"pt"}, Usage: "Pass args to proxy assumer"},
		&cli.BoolFlag{Name: "active-role", Aliases: []string{"ar"}, Usage: "Open console using active role"},
		&cli.BoolFlag{Name: "verbose", Usage: "Log debug messages"},
		&cli.StringFlag{Name: "active-aws-profile", EnvVars: []string{"AWS_PROFILE"}, Hidden: true},
		&cli.BoolFlag{Name: "auto-configure-shell", Usage: "Configure shell alias without prompts"},
		&cli.StringFlag{Name: "exec", Usage: "Assume a profile then execute this command"},
		&cli.StringFlag{Name: "duration", Aliases: []string{"d"}, Usage: "Set session duration for your assumed role"},
		&cli.BoolFlag{Name: "sso", Usage: "Assume an account and role with provided SSO flags"},
		&cli.StringFlag{Name: "sso-start-url", Usage: "Use this in conjunction with --sso, the sso-start-url"},
		&cli.StringFlag{Name: "sso-region", Usage: "Use this in conjunction with --sso, the sso-region"},
		&cli.StringFlag{Name: "account-id", Usage: "Use this in conjunction with --sso, the account-id"},
		&cli.StringFlag{Name: "role-name", Usage: "Use this in conjunction with --sso, the role-name"},
		&cli.StringFlag{Name: "browser-profile", Aliases: []string{"bp"}, Usage: "Use a pre-existing profile in your browser", EnvVars: []string{"GRANTED_BROWSER_PROFILE"}},
		&cli.StringFlag{Name: "mfa-token", Usage: "Provide your current MFA token for the role you are assuming to skip being prompted"},
		&cli.StringFlag{Name: "save-to", Usage: "Use this in conjunction with --sso, the profile name to save the role to in your AWS config file"},
		&cli.BoolFlag{Name: "export-all-env-vars", Aliases: []string{"x"}, Usage: "Exports all available credentials to the terminal when used with a profile configured for credential-process. Without this flag, only the AWS_PROFILE will be configured"},
		&cli.StringFlag{Name: "aws-config-file"},
		&cli.StringFlag{Name: "chain", Usage: "Assume a given role ARN using the profile selected"},
		&cli.StringFlag{Name: "reason", Usage: "Provide a reason for requesting access to the role"},
		&cli.BoolFlag{Name: "confirm", Aliases: []string{"y"}, Usage: "Skip confirmation prompts for access requests"},
		&cli.BoolFlag{Name: "wait", Usage: "When using Granted with Common Fate the assume will halt while waiting for the access request to be approved."},
		&cli.BoolFlag{Name: "no-cache", Usage: "Disables caching of session credentials and forces a refresh", EnvVars: []string{"GRANTED_NO_CACHE"}},
		&cli.StringSliceFlag{Name: "browser-launch-template-arg", Usage: "Additional arguments to provide to the browser launch template command in key=value format, e.g. '--browser-launch-template-arg foo=bar"},
		&cli.BoolFlag{Name: "skip-profile-registry-sync", Usage: "You can use this to skip the automated profile registry sync process."},
		&cli.StringSliceFlag{Name: "attach", Usage: "Attach justifications to your request, such as a Jira ticket id or url `--attach=TP-123`"},
	}
}

func GetCliApp() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		ver := fmt.Sprintf("Granted version: %s\n", build.Version)
		fmt.Print(assumeprint.SafeOutput(ver))
	}

	app := &cli.App{
		Name:                 "assume",
		Writer:               os.Stderr,
		Usage:                "https://granted.dev",
		UsageText:            "assume [options][Profile]",
		Version:              build.Version,
		HideVersion:          false,
		Flags:                GlobalFlags(),
		Action:               AssumeCommand,
		EnableBashCompletion: true,
		BashComplete:         Completion,
		Before: func(c *cli.Context) error {
			if c.String("aws-config-file") != "" {
				_ = os.Setenv("AWS_CONFIG_FILE", c.String("aws-config-file"))
			}
			// unsets the exported env vars
			if c.Bool("unset") {
				err := UnsetAction(c)
				if err != nil {
					return err
				}
				os.Exit(0)
			}

			clio.SetLevelFromEnv("GRANTED_LOG")
			zap.ReplaceGlobals(clio.G())
			if c.Bool("verbose") {
				clio.SetLevelFromString("debug")
			}
			err := ValidateSSOFlags(c)
			if err != nil {
				return err
			}

			grantedFolder, err := config.GrantedStateFolder()
			if err != nil {
				return err
			}

			logfilepath := path.Join(grantedFolder, "log")
			clio.SetFileLogging(cliolog.FileLoggerConfig{
				Filename: logfilepath,
			})

			if err := config.SetupConfigFolder(); err != nil {
				return err
			}

			hasSetup, err := browser.UserHasDefaultBrowser(c)
			if err != nil {
				return err
			}

			err = chromemsg.ConfigureHost()
			if err != nil {
				clio.Debugf("error configuring Granted browser extension native messaging manifest: %s", err.Error())
			}

			if !hasSetup {
				browserName, err := browser.HandleBrowserWizard(c)
				if err != nil {
					return err
				}

				// see if they want to set their sso browser the same as their granted default
				err = browser.SSOBrowser(browserName)
				if err != nil {
					return err
				}

				// run instructions
				// terminates the command with os.exit(0)
				browser.GrantedIntroduction()
			}

			if !c.Bool("skip-profile-registry-sync") {
				// Sync granted profile registries if enabled
				autosync.Run(c.Context, true)
			} else {
				clio.Debug("skipping profile registry sync because --skip-profile-registry-sync flag was true")
			}

			// Setup the shell alias
			if os.Getenv("FORCE_NO_ALIAS") != "true" {
				return alias.MustBeConfigured(c.Bool("auto-configure-shell"))
			}

			return nil
		},
	}

	app.EnableBashCompletion = true

	return app
}
