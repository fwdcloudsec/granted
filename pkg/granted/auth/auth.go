package auth

import (
	"fmt"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:  "auth",
	Usage: "Manage OIDC authentication for Granted",
	Flags: []cli.Flag{},
	Subcommands: []*cli.Command{
		&loginCommand,
		&logoutCommand,
	},
}

var loginCommand = cli.Command{
	Name:  "login",
	Usage: "Authenticate to an access provider",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "url", Usage: "The access provider URL to authenticate with"},
	},
	Action: func(c *cli.Context) error {
		providerURL := c.String("url")
		if providerURL == "" {
			providerURL = c.Args().First()
		}
		if providerURL == "" {
			return fmt.Errorf("please provide a provider URL, e.g. 'granted auth login https://provider.example.com'")
		}

		cfg, err := providercfg.LoadFromURL(c.Context, providerURL)
		if err != nil {
			return fmt.Errorf("failed to load provider config from %s: %w", providerURL, err)
		}

		// TODO: implement OIDC login flow using cfg.Auth
		clio.Infof("Provider config loaded from %s (auth type: %s, issuer: %s)", providerURL, cfg.Auth.Type, cfg.Auth.Issuer)
		clio.Warn("OIDC login flow is not yet implemented. Please authenticate via your browser.")

		return nil
	},
}

var logoutCommand = cli.Command{
	Name:  "logout",
	Usage: "Log out of an access provider",
	Action: func(c *cli.Context) error {
		// TODO: implement logout (clear stored tokens)
		clio.Info("Logout is not yet implemented")
		return nil
	},
}
