package registry

import (
	"fmt"
	"os"
	"path"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"gopkg.in/ini.v1"
)

// getDefaultAWSConfigLocation returns the AWS config file path,
// respecting the AWS_CONFIG_FILE environment variable per
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
func getDefaultAWSConfigLocation() (string, error) {
	return cfaws.GetAWSConfigPath(), nil
}

// loadAWSConfigFile loads the `~/.aws/config` file, and creates it if it doesn't exist.
func loadAWSConfigFile() (*ini.File, string, error) {
	filepath, err := getDefaultAWSConfigLocation()
	if err != nil {
		return nil, "", err
	}

	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		clio.Infof("created AWS config file: %s", filepath)

		// create all parent directory if necessary.
		err := os.MkdirAll(path.Dir(filepath), USER_READ_WRITE_PERM)
		if err != nil {
			return nil, "", err
		}

		_, err = os.Create(filepath)
		if err != nil {
			return nil, "", fmt.Errorf("unable to create AWS config file: %w", err)
		}
	}

	awsConfig, err := loadAWSConfigFileFromPath(filepath)
	if err != nil {
		return nil, "", err
	}
	return awsConfig, filepath, nil
}

func loadAWSConfigFileFromPath(filepath string) (*ini.File, error) {
	awsConfig, err := ini.LoadSources(ini.LoadOptions{
		SkipUnrecognizableLines: true,
		AllowNonUniqueSections:  true,
		AllowNestedValues:       true,
	}, filepath)
	if err != nil {
		return nil, err
	}

	return awsConfig, nil
}
