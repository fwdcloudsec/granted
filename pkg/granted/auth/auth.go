package auth

import (
	"fmt"
	"time"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/idclogin"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
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

		if cfg.Auth.Type != "oidc" {
			return fmt.Errorf("unsupported auth type '%s' for provider at %s (expected 'oidc')", cfg.Auth.Type, providerURL)
		}

		output, err := idclogin.ProviderLogin(c.Context, idclogin.ProviderLoginInput{
			IssuerURL: cfg.Auth.Issuer,
			ClientID:  cfg.Auth.ClientID,
			Scopes:    cfg.Auth.Scopes,
		})
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		tokenStorage := securestorage.NewProviderTokenStorage()
		err = tokenStorage.StoreToken(providerURL, securestorage.ProviderToken{
			AccessToken:  output.AccessToken,
			RefreshToken: output.RefreshToken,
			IDToken:      output.IDToken,
			TokenType:    output.TokenType,
			Expiry:       time.Now().Add(time.Duration(output.ExpiresIn) * time.Second),
			ProviderURL:  providerURL,
		})
		if err != nil {
			return fmt.Errorf("failed to store token: %w", err)
		}

		clio.Successf("Successfully authenticated to %s (%s)", cfg.Provider, providerURL)
		return nil
	},
}

var logoutCommand = cli.Command{
	Name:  "logout",
	Usage: "Log out of an access provider",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "url", Usage: "The access provider URL to log out from"},
	},
	Action: func(c *cli.Context) error {
		providerURL := c.String("url")
		if providerURL == "" {
			providerURL = c.Args().First()
		}
		if providerURL == "" {
			return fmt.Errorf("please provide a provider URL, e.g. 'granted auth logout https://provider.example.com'")
		}

		tokenStorage := securestorage.NewProviderTokenStorage()
		err := tokenStorage.ClearToken(providerURL)
		if err != nil {
			return fmt.Errorf("failed to clear token: %w", err)
		}

		clio.Successf("Logged out from %s", providerURL)
		return nil
	},
}
