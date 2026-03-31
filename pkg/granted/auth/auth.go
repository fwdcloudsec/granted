package auth

import (
	"github.com/common-fate/cli/cmd/cli/command"
	"github.com/common-fate/clio"
	"github.com/common-fate/sdk/config"
	"github.com/common-fate/sdk/loginflow"
	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:  "auth",
	Usage: "Manage OIDC authentication for Granted",
	Flags: []cli.Flag{},
	Subcommands: []*cli.Command{
		&command.Configure,
		&loginCommand,
		&logoutCommand,
		&command.Context,
	},
}

var loginCommand = cli.Command{
	Name:  "login",
	Usage: "Authenticate to an OIDC provider",
	Action: func(c *cli.Context) error {
		cfg, err := config.LoadDefault(c.Context)
		if err == config.ErrConfigFileNotFound {
			clio.Errorf("The Common Fate config file (~/.cf/config by default) was not found. To fix this, run 'granted auth configure https://commonfate.example.com' (replacing the URL in the command with your Common Fate deployment URL")
		}
		if err != nil {
			return err
		}

		lf := loginflow.NewFromConfig(cfg)

		return lf.Login(c.Context)
	},
}

var logoutCommand = cli.Command{
	Name:  "logout",
	Usage: "Log out of an OIDC provider",
	Action: func(c *cli.Context) error {
		cfg, err := config.LoadDefault(c.Context)
		if err == config.ErrConfigFileNotFound {
			clio.Errorf("The Common Fate config file (~/.cf/config by default) was not found. To fix this, run 'granted auth configure https://commonfate.example.com' (replacing the URL in the command with your Common Fate deployment URL")
		}
		if err != nil {
			return err
		}

		return cfg.TokenStore.Clear()
	},
}
