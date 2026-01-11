package registry

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

// Profile Registry data structure has been updated to accomodate different registry level options.
// If any user is using the previous configuration then prompt user to update the registry values.
var MigrateCommand = cli.Command{
	Name:        "migrate",
	Description: "Migrate Profile Registry Configuration",
	Usage:       "Migrate Profile Registry Configuration",

	Action: func(c *cli.Context) error {
		gConf, err := grantedConfig.Load()
		if err != nil {
			clio.Debug(err.Error())
		}

		if len(gConf.ProfileRegistryURLS) > 0 {
			var registries []grantedConfig.Registry
			for i, u := range gConf.ProfileRegistryURLS {
				var msg survey.Input
				if i > 0 {
					msg = survey.Input{Message: fmt.Sprintf("Enter a registry name for %s", u), Default: fmt.Sprintf("granted-registry-%d", i)}
				} else {
					msg = survey.Input{Message: fmt.Sprintf("Enter a registry name for %s", u), Default: "granted-registry"}
				}

				var selected string
				err := testable.AskOne(&msg, &selected)
				if err != nil {
					return err
				}

				registries = append(registries, grantedConfig.Registry{
					Name: selected,
					URL:  u,
				})

			}

			gConf.ProfileRegistry.Registries = registries
			gConf.ProfileRegistryURLS = nil

			err = gConf.Save()
			if err != nil {
				clio.Debug(err.Error())
				return err
			}

			clio.Success("Successfully migrated your configuration.")

			return nil
		}

		clio.Infof("Your Profile Registry already has the latest configuration. No action required.")

		return nil
	},
}

func IsOutdatedConfig() bool {
	gConf, err := grantedConfig.Load()
	if err != nil {
		clio.Debug(err.Error())
		return true
	}

	return len(gConf.ProfileRegistryURLS) > 0
}
