package registry

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/granted/awsmerge"
	"github.com/fwdcloudsec/granted/pkg/granted/registry/gitregistry"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

var RemoveCommand = cli.Command{
	Name:        "remove",
	Description: "Unsubscribe from a Profile Registry",
	Usage:       "Unsubscribe from a Profile Registry",

	Action: func(c *cli.Context) error {
		gConf, err := grantedConfig.Load()
		if err != nil {
			return err
		}

		if len(gConf.ProfileRegistry.Registries) == 0 {
			clio.Error("There are no profile registries configured currently.\n Please use 'granted registry add <https://github.com/your-org/your-registry.git>' to add a new registry")
			return nil
		}

		registriesWithNames := []string{}

		for _, r := range gConf.ProfileRegistry.Registries {
			registriesWithNames = append(registriesWithNames, r.Name)
		}

		in := survey.Select{Message: "Please select the git repository you would like to unsubscribe:", Options: registriesWithNames}
		var out string
		err = testable.AskOne(&in, &out)
		if err != nil {
			return err
		}

		var selectedRegistry grantedConfig.Registry

		for _, r := range gConf.ProfileRegistry.Registries {
			if r.Name == out {
				selectedRegistry = r
			}
		}

		reg, err := gitregistry.New(gitregistry.Opts{
			Name:     selectedRegistry.Name,
			URL:      selectedRegistry.URL,
			Path:     selectedRegistry.Path,
			Filename: selectedRegistry.Filename,
		})
		if err != nil {
			return err
		}

		configFile, awsConfigPath, err := loadAWSConfigFile()
		if err != nil {
			return err
		}

		awsmerge.RemoveRegistry(configFile, selectedRegistry.Name)

		err = configFile.SaveTo(awsConfigPath)
		if err != nil {
			return err
		}

		err = reg.Delete()
		if err != nil {
			return err
		}

		err = remove(gConf, out)
		if err != nil {
			return err
		}

		err = gConf.Save()
		if err != nil {
			return err
		}

		clio.Successf("Successfully unsubscribed from %s", out)

		return nil
	},
}

func remove(gConf *grantedConfig.Config, rName string) error {
	registries := gConf.ProfileRegistry.Registries

	var index = -1
	for i := 0; i < len(registries); i++ {
		if registries[i].Name == rName {
			index = i
		}
	}

	if index > -1 {
		registries = append(registries[:index], registries[index+1:]...)
	}

	gConf.ProfileRegistry.Registries = registries

	err := gConf.Save()
	if err != nil {
		return err
	}

	return nil
}
