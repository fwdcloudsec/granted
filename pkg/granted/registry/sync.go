package registry

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/granted/awsmerge"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

const (
	SyncTempDirPrefix = "granted-registry-sync"
)

var SyncCommand = cli.Command{
	Name:        "sync",
	Usage:       "Pull the latest change from remote origin and sync aws profiles in aws config files",
	Description: "Pull the latest change from remote origin and sync aws profiles in aws config files",
	Action: func(c *cli.Context) error {
		if err := SyncProfileRegistries(c.Context, true); err != nil {
			return err
		}

		return nil
	},
}

// Wrapper around sync func. Check if profile registry is configured, pull the latest changes and call sync func.
// promptUserIfProfileDuplication if true will automatically prefix the duplicate profiles and won't prompt users
// this is useful when new registry with higher priority is added and there is duplication with lower priority registry.
func SyncProfileRegistries(ctx context.Context, interactive bool) error {
	registries, err := GetProfileRegistries(interactive)
	if err != nil {
		return err
	}

	if len(registries) == 0 {
		clio.Warn("granted registry not configured. Try adding a git repository with 'granted registry add <https://github.com/your-org/your-registry.git>'")
	}

	configFile, awsConfigPath, err := loadAWSConfigFile()
	if err != nil {
		return err
	}

	if configFile == nil {
		// prevent a panic reported by a user due to configFile being empty.
		// It is likely this is caused by Granted being run for the first time on
		// a device that does not have AWS profiles set up.
		return nil
	}

	for _, r := range registries {
		src, err := r.Registry.AWSProfiles(ctx, interactive)
		if err != nil {
			return fmt.Errorf("error retrieving AWS profiles for registry %s: %w", r.Config.Name, err)
		}

		merged, err := awsmerge.WithRegistry(src, configFile, awsmerge.RegistryOpts{
			Name:                    r.Config.Name,
			PrefixAllProfiles:       r.Config.PrefixAllProfiles,
			PrefixDuplicateProfiles: r.Config.PrefixDuplicateProfiles,
		})
		var dpe awsmerge.DuplicateProfileError
		if interactive && errors.As(err, &dpe) {
			clio.Warnf(err.Error())

			const (
				DUPLICATE = "Add registry name as prefix to all duplicate profiles for this registry"
				ABORT     = "Abort, I will manually fix this"
			)

			options := []string{DUPLICATE, ABORT}

			in := survey.Select{Message: "Please select which option would you like to choose to resolve: ", Options: options}
			var selected string
			withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
			err = testable.AskOne(&in, &selected, withStdio)
			if err != nil {
				return err
			}

			if selected == ABORT {
				return fmt.Errorf("aborting sync for registry %s", r.Config.Name)
			}

			// try and merge again
			merged, err = awsmerge.WithRegistry(src, configFile, awsmerge.RegistryOpts{
				Name:                    r.Config.Name,
				PrefixAllProfiles:       r.Config.PrefixAllProfiles,
				PrefixDuplicateProfiles: true,
			})
			if err != nil {
				return fmt.Errorf("error after trying to merge profiles again for registry %s: %w", r.Config.Name, err)
			}
		}
		if err != nil {
			return fmt.Errorf("error after trying to merge profiles for registry %s: %w", r.Config.Name, err)
		}

		configFile = merged
	}

	// Update the AWS config file only if all syncs have succeeded
	err = configFile.SaveTo(awsConfigPath)
	if err != nil {
		return fmt.Errorf("error saving AWS config to %s: %w", awsConfigPath, err)
	}

	return nil
}
